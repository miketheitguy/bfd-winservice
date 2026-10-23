using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Drawing.Text;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Xml;

public static class BfdAnimation {
    static Color bg=Color.FromArgb(11,18,32), panel=Color.FromArgb(22,36,59), white=Color.FromArgb(237,244,255), muted=Color.FromArgb(163,181,208), blue=Color.FromArgb(106,159,255), green=Color.FromArgb(66,221,175), red=Color.FromArgb(255,113,128), amber=Color.FromArgb(255,202,105), line=Color.FromArgb(69,86,113);
    static Graphics g;
    static Color[] palette;
    static Dictionary<int,byte> lookup=new Dictionary<int,byte>();
    static Dictionary<string,RectangleF> nodes=new Dictionary<string,RectangleF>();
    static Color purple=Color.FromArgb(193,160,255);
    static PointF[] primary={new PointF(280,315),new PointF(440,315)};
    static PointF[] secondary={new PointF(280,525),new PointF(440,525)};
    static PointF[] client={new PointF(810,400),new PointF(710,400)};
    static Font F(float size,bool bold=false) { return new Font("Segoe UI",size,bold?FontStyle.Bold:FontStyle.Regular,GraphicsUnit.Pixel); }
    static void Text(string s,float x,float y,float size,Color color,bool bold=false) {
        using(var f=F(size,bold)) using(var b=new SolidBrush(color)) g.DrawString(s,f,b,x,y,StringFormat.GenericTypographic);
    }
    static void Center(string s,float x,float y,float size,Color color,bool bold=false) {
        using(var f=F(size,bold)) using(var b=new SolidBrush(color)) using(var sf=new StringFormat()) {sf.Alignment=StringAlignment.Center;g.DrawString(s,f,b,x,y,sf);}
    }
    static void Box(float x,float y,float w,float h,Color fill,Color stroke,float r=14) {
        using(var p=new GraphicsPath()) {p.AddArc(x,y,r*2,r*2,180,90);p.AddArc(x+w-2*r,y,2*r,2*r,270,90);p.AddArc(x+w-2*r,y+h-2*r,2*r,2*r,0,90);p.AddArc(x,y+h-2*r,2*r,2*r,90,90);p.CloseFigure();using(var b=new SolidBrush(fill))g.FillPath(b,p);if(stroke.A>0)using(var pen=new Pen(stroke,1.5f))g.DrawPath(pen,p);}
    }
    static void Path(PointF[] points,Color color,float width=4) {using(var p=new Pen(color,width)){p.LineJoin=LineJoin.Round;g.DrawLines(p,points);}}
    static PointF Along(PointF[] points,double fraction,float offset=0) {
        double length=0;for(int i=1;i<points.Length;i++)length+=Math.Abs(points[i].X-points[i-1].X)+Math.Abs(points[i].Y-points[i-1].Y);
        double distance=fraction*length;for(int i=1;i<points.Length;i++){double dx=points[i].X-points[i-1].X,dy=points[i].Y-points[i-1].Y;double part=Math.Abs(dx)+Math.Abs(dy);if(distance<=part)return new PointF((float)(points[i-1].X+dx*distance/part-dy*offset/part),(float)(points[i-1].Y+dy*distance/part+dx*offset/part));distance-=part;}return points[points.Length-1];
    }
    static void Packets(PointF[] points,double t,bool probe=false,bool reverse=false,double limit=1) {
        int count=probe?2:3;for(int j=0;j<count;j++){double u=(t*(probe?.7:.45)+j/(double)count)%1;if(reverse)u=1-u;if(reverse&&limit<1?u<1-limit:u>limit)continue;var p=Along(points,u,probe?(reverse?10:-10):0);using(var b=new SolidBrush(probe?green:blue)){if(probe)g.FillEllipse(b,p.X-4,p.Y-4,8,8);else g.FillRectangle(b,p.X-5,p.Y-5,10,10);}}
    }
    static void Cross(float x,float y) {using(var p=new Pen(red,4)){g.DrawLine(p,x-7,y-7,x+7,y+7);g.DrawLine(p,x-7,y+7,x+7,y-7);}}
    static void Server(string key,string title,bool failed,bool answering) {
        var n=nodes[key];Box(n.X,n.Y,n.Width,n.Height,panel,line);Text(title,n.X+18,n.Y+13,25,white,true);
        Text(failed?"Host / path unreachable":answering?"Answering DNS queries":"DNS service ready",n.X+18,n.Y+48,17,failed?red:green,true);
        Text("203.0.113.53/32",n.X+18,n.Y+77,22,purple,true);
        Text(failed?"Last advertised via BGP":"Advertises /32 via BGP",n.X+18,n.Y+111,16,muted);
    }
    static void Advertise(float y,double t) {
        using(var p=new Pen(purple,2)){p.CustomEndCap=new AdjustableArrowCap(4,4);g.DrawLine(p,294,y,427,y);}
        Text("BGP /32",316,y-24,15,purple,true);
        float x=294+(float)((t*.35)%1)*128;using(var b=new SolidBrush(purple))g.FillPolygon(b,new[]{new PointF(x,y-5),new PointF(x+5,y),new PointF(x,y+5),new PointF(x-5,y)});
    }
    static void Dns(PointF[] points,double t,bool reverse,bool reply=false,double limit=1) {
        for(int j=0;j<2;j++){double u=(t*.65+j*.5)%1;if(reverse)u=1-u;if(reverse&&limit<1?u<1-limit:u>limit)continue;
            var p=Along(points,u,reply?5:-5);float dx=points[points.Length-1].X-points[0].X;float direction=(dx>0?1:-1)*(reverse?-1:1);
            using(var b=new SolidBrush(reply?amber:blue))g.FillPolygon(b,new[]{new PointF(p.X+6*direction,p.Y),new PointF(p.X-5*direction,p.Y-5),new PointF(p.X-5*direction,p.Y+5)});
        }
    }
    static void Frame(double t) {
        int stage=t<6?0:t<10?1:t<16?2:3;bool failed=stage>=1;bool down=stage>=2;bool switched=stage==3;bool bgpDown=t>=12;
        g.Clear(bg);g.SmoothingMode=SmoothingMode.AntiAlias;g.TextRenderingHint=TextRenderingHint.AntiAliasGridFit;
        Text("ANYCAST DNS",40,26,42,white,true);Text("One DNS address. Two servers. BFD + BGP failover.",42,82,22,muted);
        string[] phases={"Serve via A","A fails","Notify BGP","Serve via B"};
        for(int i=0;i<4;i++){float x=40+i*240;bool active=i==stage;Box(x,128,220,48,active?panel:bg,active?blue:line,10);Text((i+1).ToString("00"),x+14,140,19,active?blue:muted,true);Text(phases[i],x+53,139,20,active?white:muted,active);}
        Path(primary,failed?line:blue,4);Path(secondary,switched?blue:line,switched?4:3);Path(client,blue,4);
        if(!failed)Advertise(267,t);Advertise(477,t+.5);
        if(!down){Packets(primary,t,true,false,failed?.46:1);Packets(primary,t,true,true,failed?.46:1);}
        Packets(secondary,t+.2,true,false);Packets(secondary,t+.2,true,true);
        Dns(client,t,false);if(!failed||switched)Dns(client,t+.3,true,true);
        if(!failed){Dns(primary,t+.3,true);Dns(primary,t+.7,false,true);}else if(!bgpDown){Dns(primary,t+.3,true,false,.43);}
        if(failed){using(var p=new Pen(bg,12))g.DrawLine(p,350,315,370,315);Cross(360,315);Text("Path failed",312,341,15,red,true);}
        if(switched){Dns(secondary,t+.3,true);Dns(secondary,t+.7,false,true);}
        Server("a","Server A",failed,!failed);Server("b","Server B",false,switched);
        var c=nodes["c"];Box(c.X,c.Y,c.Width,c.Height,panel,line);Text("Router C",460,233,27,white,true);
        Box(460,276,230,40,bg,down?red:green,8);Text(down?"BFD to A: DOWN":"BFD to A: UP",477,286,20,down?red:green,true);
        if(stage==2){using(var p=new Pen(red,3)){p.CustomEndCap=new AdjustableArrowCap(4,4);g.DrawLine(p,550,320,550,352);}Text("local event",566,328,14,red);using(var b=new SolidBrush(red))g.FillEllipse(b,546,320+(float)((t-10)%1)*28,8,8);}
        else {using(var p=new Pen(line,2))g.DrawLine(p,550,320,550,351);}
        Box(460,358,230,44,bg,bgpDown?red:blue,8);Text(bgpDown?"BGP to A: DOWN":"BGP to A: UP",477,370,20,bgpDown?red:blue,true);
        Text("203.0.113.53/32",460,424,23,purple,true);
        Text(bgpDown?"via A: removed":"via A: selected (policy)",460,462,18,bgpDown?red:blue,true);
        Text(switched?"via B: SELECTED":"via B: available",460,493,18,switched?blue:muted,true);
        Text("BFD + BGP to B: UP",460,539,17,green,true);
        var d=nodes["d"];Box(d.X,d.Y,d.Width,d.Height,panel,line);Text("Client D",d.X+16,d.Y+15,25,white,true);Text("DNS queries to",d.X+16,d.Y+53,16,muted);Text("203.0.113.53",d.X+16,d.Y+79,18,blue,true);Text("UDP / 53",d.X+16,d.Y+111,15,muted);
        Text(!failed?"Replies from A":switched?"Replies from B":"DNS retries",797,491,17,!failed||switched?amber:muted,true);
        if(stage==1){int ms=(int)Math.Min(299,((t-6)/4)*300);Text(ms.ToString()+" / 300 ms",300,382,17,amber,true);}
        using(var b=new SolidBrush(purple))g.FillPolygon(b,new[]{new PointF(45,592),new PointF(50,597),new PointF(45,602),new PointF(40,597)});Text("BGP /32 advertisement",60,586,16,muted);
        using(var b=new SolidBrush(green))g.FillEllipse(b,298,592,9,9);Text("BFD probes",316,586,16,muted);
        using(var b=new SolidBrush(blue))g.FillPolygon(b,new[]{new PointF(478,597),new PointF(468,592),new PointF(468,602)});Text("DNS query",489,586,16,muted);
        using(var b=new SolidBrush(amber))g.FillPolygon(b,new[]{new PointF(657,597),new PointF(647,592),new PointF(647,602)});Text("DNS reply",668,586,16,muted);
        Box(40,617,920,70,panel,Color.Transparent,12);
        string title,subtitle;
        if(stage==0){title="Both DNS servers advertise the same /32. Router C prefers A.";subtitle="Client D queries 203.0.113.53; Router C forwards to Server A.";}
        else if(stage==1){title="Server A becomes unreachable. BFD probes stop arriving at C.";subtitle="Example: 100 ms interval x 3 = 300 ms detection. BFD to B stays UP.";}
        else if(stage==2){title=t<12?"Inside Router C: BFD signals Down to BGP.":"Router C closes A's BGP session and removes A's /32 route.";subtitle="Client D retries the DNS query while routing converges.";}
        else {title="Router C selects Server B's /32. DNS queries now reach B.";subtitle="The client keeps the same DNS address: 203.0.113.53.";}
        Text(title,60,627,22,white,true);Text(subtitle,60,660,17,muted);
        Text("Host / path failure; no Graceful Restart. Events slowed; timing not to scale.",40,697,13,muted);
        Text("RFC 4786 / 5882",845,697,13,muted);
        using(var b=new SolidBrush(blue))g.FillRectangle(b,0,717,(float)(1000*t/28),3);
    }
    static Bitmap Indexed(Bitmap input) {
        var output=new Bitmap(input.Width,input.Height,PixelFormat.Format8bppIndexed);var cp=output.Palette;for(int i=0;i<256;i++)cp.Entries[i]=palette[i];output.Palette=cp;
        var r=new Rectangle(0,0,input.Width,input.Height);var src=input.LockBits(r,ImageLockMode.ReadOnly,PixelFormat.Format32bppArgb);var dst=output.LockBits(r,ImageLockMode.WriteOnly,PixelFormat.Format8bppIndexed);
        byte[] rgb=new byte[src.Stride*src.Height];byte[] idx=new byte[dst.Stride*dst.Height];Marshal.Copy(src.Scan0,rgb,0,rgb.Length);
        for(int y=0;y<input.Height;y++)for(int x=0;x<input.Width;x++){int k=y*src.Stride+x*4;int key=rgb[k+2]<<16|rgb[k+1]<<8|rgb[k];byte value;if(!lookup.TryGetValue(key,out value)){int min=int.MaxValue;value=0;for(int c=0;c<palette.Length;c++){int dr=rgb[k+2]-palette[c].R,dg=rgb[k+1]-palette[c].G,db=rgb[k]-palette[c].B;int dist=dr*dr+dg*dg+db*db;if(dist<min){min=dist;value=(byte)c;}}lookup[key]=value;}idx[y*dst.Stride+x]=value;}
        Marshal.Copy(idx,0,dst.Scan0,idx.Length);input.UnlockBits(src);output.UnlockBits(dst);return output;
    }
    public static void Render(string root) {
        var xml=new XmlDocument();xml.Load(System.IO.Path.Combine(root,"bfd-bgp-topology.drawio"));foreach(XmlNode n in xml.SelectNodes("//mxCell[@vertex='1']")){var p=n.SelectSingleNode("mxGeometry");nodes[n.Attributes["id"].Value]=new RectangleF(float.Parse(p.Attributes["x"].Value),float.Parse(p.Attributes["y"].Value),float.Parse(p.Attributes["width"].Value),float.Parse(p.Attributes["height"].Value));}
        var colors=new List<Color>();Color[] bases={bg,panel,white,muted,blue,green,red,amber,line,purple};foreach(var c in bases)colors.Add(c);foreach(var c in bases)foreach(var back in new[]{bg,panel})for(int v=1;v<=12;v++)colors.Add(Color.FromArgb(back.R+(c.R-back.R)*v/13,back.G+(c.G-back.G)*v/13,back.B+(c.B-back.B)*v/13));while(colors.Count<256)colors.Add(bg);palette=colors.ToArray();
        Directory.CreateDirectory(System.IO.Path.Combine(root,".frames"));using(var image=new Bitmap(1000,720,PixelFormat.Format32bppArgb))using(g=Graphics.FromImage(image))using(var contact=new Bitmap(1000,720))using(var cg=Graphics.FromImage(contact)){
            int[] preview={24,64,104,160};for(int i=0;i<224;i++){Frame(i/8.0);using(var indexed=Indexed(image))indexed.Save(System.IO.Path.Combine(root,".frames","frame-"+i.ToString("D3")+".gif"),ImageFormat.Gif);for(int j=0;j<4;j++)if(i==preview[j]){image.Save(System.IO.Path.Combine(root,"preview-"+(j+1)+".png"),ImageFormat.Png);cg.DrawImage(image,new Rectangle((j%2)*500,(j/2)*360,500,360));}if(i%56==0)Console.WriteLine("Rendered "+i+" / 224");}contact.Save(System.IO.Path.Combine(root,"contact-sheet.png"),ImageFormat.Png);
        }
    }
}

const fs = require('fs');
const file = process.argv[2];
let xml = fs.readFileSync(file, 'utf8');
const diagram = xml.match(/<mxfile[\s\S]*?<\/mxfile>|<mxGraphModel[\s\S]*?<\/mxGraphModel>/);
if (diagram && xml.trim() !== diagram[0]) xml = diagram[0];
xml = xml.replace(/="([^"]*)"/g, (m, v) => '="' + v.replace(/</g, '&lt;').replace(/&(?!(?:amp|lt|gt|quot|apos|#[0-9]+|#x[0-9a-fA-F]+);)/g, '&amp;') + '"');
xml = xml.replace(/<mxCell id="([^"]+)" parent="\1"\s*\/>/g, '<mxCell id="$1" parent="0"/>');
fs.writeFileSync(file, xml);

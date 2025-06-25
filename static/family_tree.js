// static/family_tree.js

document.addEventListener('DOMContentLoaded', function () {
  if (!window.familyTreeData) return;
  const data = window.familyTreeData;
  const width = 1000, height = 600;
  const svg = d3.select("#tree")
    .append("svg")
    .attr("width", width)
    .attr("height", height)
    .append("g")
    .attr("transform", "translate(40,0)");
  const treeLayout = d3.tree().size([height, width - 160]);
  const root = d3.hierarchy(data[0]);
  treeLayout(root);
  svg.selectAll('.link')
    .data(root.links())
    .enter()
    .append('path')
    .attr('class', 'link')
    .attr('d', d3.linkHorizontal()
      .x(function(d) { return d.y; })
      .y(function(d) { return d.x; })
    );
  const node = svg.selectAll('.node')
    .data(root.descendants())
    .enter()
    .append('g')
    .attr('class', 'node')
    .attr('transform', function(d) { return `translate(${d.y},${d.x})`; });
  node.append('circle')
    .attr('r', 7);
  node.append('text')
    .attr('dy', 4)
    .attr('x', function(d) { return d.children ? -14 : 14; })
    .style('text-anchor', function(d) { return d.children ? 'end' : 'start'; })
    .text(function(d) { return d.data.name; });
}); 
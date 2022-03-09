# Elephant_flows

In-Network detection of attacks using Random Forests

Please cite this paper if you use this code:

`Jong-Hyouk Lee and Kamal Singh, "SwitchTree: In-network Computing and Traffic Analyses with Random Forests", Neural Computing and Applications (2020)`

## Table of Contents
* [Background](#background)
* [Questions](#questions)
  * [Which side wins more?](#which-side-wins-more)
  * [What is the average game length?](#average-game-length)
  * [What are the differences between blue and red side?](#blue-vs-red)
  * [What factors are most impactful to winning? (Win Correlations)](#win-correlations)
* [Usage](#usage)


## Background
We perform in-network analysis of the network data by exploiting the power of programmable data planes. 
SwitchTree coded in P4 embeds Random Forest algorithm inside a programmable switch such that the 
Random Forest is configurable and re-configurable at runtime. We show how some flow level 
stateful features can be estimated, such as the round trip time and bitrate of each flow. 
Main references for this work are [IISY](https://github.com/cucl-srg/IIsy) and [pForest](https://arxiv.org/abs/1909.05680).

## Questions

### Which side wins more?

Historically, it was known that blue side has a higher win rate. Let's see if that is still true in high elo.


### Average Game Length

Average game length: 23.89 minutes


### Blue vs Red


### Win Correlations

As expected, each property generally yields the same correlation whether you're on red side or blue side. More of everything, except deaths, proves a greater chance to winning. Break the enemy base, and you'll win.

One thing to note here, in terms of playstyle, is that it seems dragon control is more beneficial than baron. Additionally, warding and vision have very little correlation to winning relative to other factors. Although a small difference, the team who gets the first tower generally wins more than if a team has more kills than the other

Surprisingly, the correlation between wards placed/killed to wins is low. It's an understanding that vision equals winning, but according to statistics there is little affect.

## Usage

This project is best viewed in a notebook viewer, which can be accessed [here](https://nbviewer.org/github/davidcamilo0710/LeagueOfLegendsAnalysis/blob/42d88b777ab6ca2e8c40de22e810315ff85354a2/league-of-legends-EDA.ipynb). In this notebook, you will find a walk through of the work done and the respective code.

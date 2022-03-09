# Elephant_flows

## Table of Contents
* [Background](#background)
* [Questions](#questions)
  * [Which side wins more?](#which-side-wins-more)
  * [What is the average game length?](#average-game-length)
  * [What are the differences between blue and red side?](#blue-vs-red)
  * [What factors are most impactful to winning? (Win Correlations)](#win-correlations)
* [Usage](#usage)


## Background
League of Legends is a popular video game made by RIOT Games that I have been playing since 2013. Since then, I have always tried finding new ways to get better at the game to climb up the ranking system. What if I could use data to gain an edge by discovering what contributes most to winning? Are there predetermined variables, such as which side you are on, that contribute to whether you win or not? 

In this data analysis, I answer these questions!

## Questions

### Which side wins more?

Historically, it was known that blue side has a higher win rate. Let's see if that is still true in high elo.

![piechart](https://user-images.githubusercontent.com/50093891/80163054-cd52f080-8589-11ea-86cf-6b70a535e3be.png)


### Average Game Length

Average game length: 23.89 minutes

![gamelength](https://user-images.githubusercontent.com/50093891/80163072-d93eb280-8589-11ea-912a-a32626bdb415.png)


### Blue vs Red
![bluevsred](https://user-images.githubusercontent.com/50093891/80163095-e8bdfb80-8589-11ea-862a-b735743f7670.png)


### Win Correlations
![wincorrelations](https://user-images.githubusercontent.com/50093891/80163165-1a36c700-858a-11ea-8698-00f01910f6b8.png)

As expected, each property generally yields the same correlation whether you're on red side or blue side. More of everything, except deaths, proves a greater chance to winning. Break the enemy base, and you'll win.

One thing to note here, in terms of playstyle, is that it seems dragon control is more beneficial than baron. Additionally, warding and vision have very little correlation to winning relative to other factors. Although a small difference, the team who gets the first tower generally wins more than if a team has more kills than the other

Surprisingly, the correlation between wards placed/killed to wins is low. It's an understanding that vision equals winning, but according to statistics there is little affect.

## Usage

This project is best viewed in a notebook viewer, which can be accessed [here](https://nbviewer.org/github/davidcamilo0710/LeagueOfLegendsAnalysis/blob/42d88b777ab6ca2e8c40de22e810315ff85354a2/league-of-legends-EDA.ipynb). In this notebook, you will find a walk through of the work done and the respective code.

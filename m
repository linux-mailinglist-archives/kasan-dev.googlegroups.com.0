Return-Path: <kasan-dev+bncBCR4DL77YAGRBYU2SSVQMGQEGL3FYYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 290A97FACB5
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Nov 2023 22:43:00 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-2859d0d09a3sf4026168a91.0
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Nov 2023 13:43:00 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701121378; x=1701726178; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=P1S+9w1A/Kjmv8s6ebIqiYlYYmS0yUkmNy88VN8JuEs=;
        b=e4A+yN4eyq0LovQpdcLBQFHySfl2B1GFPQcTQ+lKOJRlksmLFdxoKfjqrEyq9zhFEz
         kluMhx+7mdfDiUi3rqRVJT/bKQy70h/ORbloY7NotA12lPKyhljdvCcZXPIGSFRWkjrx
         pmyog9/WXdSihIM+p+16BLJcQdIiVQ/0FsMhCIotJ1x2bLDDjpvjrwj6dgo7/aRM8BWJ
         RGVgGGtsN8B4o6KyoHQNm4/XVR4awyIqBZhv5viWgxHxUnNAAevvwkj68N0uRbDuh1I9
         1RttT+8qw0C6uL6C6StT/CM0qK1QpBHNhdGThxB/TO693zqp2g0oxDWwrY3N6BzxT37t
         Nl5A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1701121378; x=1701726178; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=P1S+9w1A/Kjmv8s6ebIqiYlYYmS0yUkmNy88VN8JuEs=;
        b=eKxPhhtpoJ2cN8r36GeOfFwrmv0Wc5FSqNSmBAnZPjhRUMweguMeEF+nF2TsYevudX
         NIOE3y7vI3rWC8T3i3etpbM4fd6Ybxt14vJ5HYrJZ2wAX3LVM4L3H6b9miqWS7AsQ9cW
         OlImfiTYcUlGucYcxj3yOnfM17mP0hT2ak40fELISniZuNFNn1svqTH4tLzpZAtocKud
         NAZ5KRJpdtM24WYfim41u+UvXkBaiihTfYeUcwFuNuww7DhqP61NguMJvzSSKnlTLm4q
         vcpYKgDcx7QZB1xwa8y0K9Af33EKwGJ/JTqfbOaAXK6n4jtX0NJ0qh8uQ+0mOdex1mcI
         HT4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701121378; x=1701726178;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:message-id:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=P1S+9w1A/Kjmv8s6ebIqiYlYYmS0yUkmNy88VN8JuEs=;
        b=K1hA1bydm05iA7MlHK7wFvXxDnKOMQG1Ip0EyEvxentn8qcynKK1PC7dtp66HpSOZv
         2ZafJDTRw8j4inDIFyLUjEv1V1OMqMeLlk/qo979u1gvtp8WJtQER0/Jn7vVWddYIP8e
         eC4ApwSZKP2NjPF+DrLvTpe8+8dflEyBxs2rzFSuOxrr1voj5C0CGaUceGmf713lK5C/
         YcS4vUYIlchEOe7m8Ie/9PK6Y/qESSTH+Mn2mpZG5/M0RLrkwASv7/6E8gLpckkewcs5
         T1iggskQxdsPjjYsTWW6dsjwCK5bd3huW0T9Gy5oXcx5c4vdk85LGZ3pixOGH8nqmmuv
         fZqg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxJu6Gf/OprF5xqIQeA/5Z159O0O3TYXMs/QhyK2c9H+PeP9W3Y
	oUW5w8ccsbln0IHybwXmkxg=
X-Google-Smtp-Source: AGHT+IFsIZRjgNo6J0E4fpSENsrpRdVJv6D8HzBs5Pra1guh/h6BCmbPvZ1k0J1vSvSchEKYaE98sA==
X-Received: by 2002:a17:90a:a08e:b0:280:3650:382a with SMTP id r14-20020a17090aa08e00b002803650382amr13606842pjp.16.1701121378662;
        Mon, 27 Nov 2023 13:42:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1898:b0:280:859:c153 with SMTP id
 mn24-20020a17090b189800b002800859c153ls275660pjb.1.-pod-prod-04-us; Mon, 27
 Nov 2023 13:42:57 -0800 (PST)
X-Received: by 2002:a17:90b:2703:b0:285:83ac:2443 with SMTP id px3-20020a17090b270300b0028583ac2443mr2706195pjb.9.1701121377500;
        Mon, 27 Nov 2023 13:42:57 -0800 (PST)
Date: Mon, 27 Nov 2023 13:42:56 -0800 (PST)
From: Nguyet Edmondson <edmondsonnguyet@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <ad9097c1-d8fd-4a0f-baf0-c0f6f17f8c34n@googlegroups.com>
Subject: Arundhati Movie In Tamil Hd 1080p
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_29550_1712330673.1701121376744"
X-Original-Sender: edmondsonnguyet@gmail.com
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

------=_Part_29550_1712330673.1701121376744
Content-Type: multipart/alternative; 
	boundary="----=_Part_29551_1011547699.1701121376744"

------=_Part_29551_1011547699.1701121376744
Content-Type: text/plain; charset="UTF-8"

Arundhati Movie In Tamil Hd 1080p: A Review of the Horror Thriller Starring 
Anushka ShettyArundhati is a 2009 Tamil horror thriller movie starring 
Anushka Shetty, Sonu Sood, and Arjan Bajwa. The movie is directed by Kodi 
Ramakrishna and produced by M. Shyam Prasad Reddy. The movie is a remake of 
the 2009 Telugu movie of the same name, which was also directed by Kodi 
Ramakrishna.

Arundhati Movie In Tamil Hd 1080p
Download https://urlgoal.com/2wGKAz


The movie revolves around Arundhati (Anushka Shetty), a descendant of a 
royal family who visits her ancestral palace for her marriage. There, she 
learns that she is the reincarnation of her great-grandmother Jejamma (also 
played by Anushka Shetty), who was a brave and benevolent queen who fought 
against a ruthless black magician named Pasupathi (Sonu Sood). Pasupathi 
had a lustful eye on Jejamma and tried to possess her, but she resisted him 
and sacrificed her life to trap him in a tomb. However, Pasupathi manages 
to escape from the tomb after many years and seeks revenge on Arundhati and 
her family. Arundhati has to face Pasupathi and his evil forces with the 
help of a friendly spirit named Anwar (Arjan Bajwa), who was Jejamma's 
lover in her previous life.
Arundhati is a movie that blends horror, action, drama, and romance in an 
engaging way. The movie has stunning visuals, impressive sets, and 
captivating music. The movie also showcases the rich culture and traditions 
of Tamil Nadu, especially the folk art forms and rituals. The movie has won 
several awards, including four Filmfare Awards South and three Nandi Awards.
Arundhati is a movie that can be enjoyed by fans of horror and thriller 
genres. The movie is available in HD 1080p quality on Disney+ Hotstar[^1^] 
and YouTube[^2^] [^3^]. The movie has a runtime of 2 hours and 5 minutes 
and is rated U/A for some violent and scary scenes.


Arundhati Movie In Tamil Hd 1080p: A Review of the Horror Thriller Starring 
Anushka ShettyArundhati is a 2009 Tamil horror thriller movie starring 
Anushka Shetty, Sonu Sood, and Arjan Bajwa. The movie is directed by Kodi 
Ramakrishna and produced by M. Shyam Prasad Reddy. The movie is a remake of 
the 2009 Telugu movie of the same name, which was also directed by Kodi 
Ramakrishna.
The movie revolves around Arundhati (Anushka Shetty), a descendant of a 
royal family who visits her ancestral palace for her marriage. There, she 
learns that she is the reincarnation of her great-grandmother Jejamma (also 
played by Anushka Shetty), who was a brave and benevolent queen who fought 
against a ruthless black magician named Pasupathi (Sonu Sood). Pasupathi 
had a lustful eye on Jejamma and tried to possess her, but she resisted him 
and sacrificed her life to trap him in a tomb. However, Pasupathi manages 
to escape from the tomb after many years and seeks revenge on Arundhati and 
her family. Arundhati has to face Pasupathi and his evil forces with the 
help of a friendly spirit named Anwar (Arjan Bajwa), who was Jejamma's 
lover in her previous life.
Arundhati is a movie that blends horror, action, drama, and romance in an 
engaging way. The movie has stunning visuals, impressive sets, and 
captivating music. The movie also showcases the rich culture and traditions 
of Tamil Nadu, especially the folk art forms and rituals. The movie has won 
several awards, including four Filmfare Awards South and three Nandi Awards.
Arundhati Movie In Tamil Hd 1080p: Cast and Crew DetailsThe movie features 
an ensemble cast of talented actors who have delivered remarkable 
performances. Anushka Shetty plays the dual role of Arundhati and Jejamma 
with grace and conviction. She portrays the contrasting personalities of 
the modern and courageous Arundhati and the traditional and heroic Jejamma 
with ease and elegance. She also underwent rigorous training in martial 
arts and sword fighting for the role. Sonu Sood plays the menacing villain 
Pasupathi with flair and intensity. He also underwent prosthetic makeup for 
his character's look. Arjan Bajwa plays the supportive and romantic Anwar 
with charm and sincerity. He also dubbed his own voice for the Tamil 
version of the movie.
The movie also features veteran actors like Kaikala Satyanarayana, 
Manorama, Sayaji Shinde, Chalapathi Rao, Annapoorna, Ahuti Prasad, 
Subhashini, Prudhviraj, Bhel Prasad, Leena Sidhu, Deepak, Divya Nagesh, and 
others in supporting roles. The movie is directed by Kodi Ramakrishna, who 
is known for his movies in fantasy and horror genres. He has also directed 
movies like Ammoru, Devi Putrudu, Devullu, Anji, etc. The movie is written 
by Chintapalli Ramana and Manav Mahapatra. The movie is produced by M. 
Shyam Prasad Reddy under his banner Mallemala Entertainments. He is also 
known for producing movies like Prema Katha Chitram, Kshana Kshanam, etc.
Arundhati Movie In Tamil Hd 1080p: Technical AspectsThe movie boasts of 
high-quality technical aspects that enhance the viewing experience. The 
cinematography by K.K. Senthil Kumar is splendid and captures the grandeur 
of the palace, the beauty of the landscapes, and the horror of the dark 
scenes. The editing by Marthand K. Venkatesh is crisp and smooth and 
maintains the pace of the movie. The music by Koti is melodious and 
haunting and suits the mood of the movie. The songs are sung by singers 
like Karthik, Harini, Malathi Lakshmanan, Kalpana Raghavendar, etc. The 
background score by Koti is also effective and creates tension and suspense 
in the scenes.
The visual effects by various artists are outstanding and realistic and 
create a convincing world of magic and mystery. The visual effects 
supervisors are San
 35727fac0c


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ad9097c1-d8fd-4a0f-baf0-c0f6f17f8c34n%40googlegroups.com.

------=_Part_29551_1011547699.1701121376744
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Arundhati Movie In Tamil Hd 1080p: A Review of the Horror Thriller Starring=
 Anushka ShettyArundhati is a 2009 Tamil horror thriller movie starring Anu=
shka Shetty, Sonu Sood, and Arjan Bajwa. The movie is directed by Kodi Rama=
krishna and produced by M. Shyam Prasad Reddy. The movie is a remake of the=
 2009 Telugu movie of the same name, which was also directed by Kodi Ramakr=
ishna.<div><br /></div><div>Arundhati Movie In Tamil Hd 1080p</div><div>Dow=
nload https://urlgoal.com/2wGKAz</div><div><br /></div><div><br /></div><di=
v>The movie revolves around Arundhati (Anushka Shetty), a descendant of a r=
oyal family who visits her ancestral palace for her marriage. There, she le=
arns that she is the reincarnation of her great-grandmother Jejamma (also p=
layed by Anushka Shetty), who was a brave and benevolent queen who fought a=
gainst a ruthless black magician named Pasupathi (Sonu Sood). Pasupathi had=
 a lustful eye on Jejamma and tried to possess her, but she resisted him an=
d sacrificed her life to trap him in a tomb. However, Pasupathi manages to =
escape from the tomb after many years and seeks revenge on Arundhati and he=
r family. Arundhati has to face Pasupathi and his evil forces with the help=
 of a friendly spirit named Anwar (Arjan Bajwa), who was Jejamma's lover in=
 her previous life.</div><div>Arundhati is a movie that blends horror, acti=
on, drama, and romance in an engaging way. The movie has stunning visuals, =
impressive sets, and captivating music. The movie also showcases the rich c=
ulture and traditions of Tamil Nadu, especially the folk art forms and ritu=
als. The movie has won several awards, including four Filmfare Awards South=
 and three Nandi Awards.</div><div>Arundhati is a movie that can be enjoyed=
 by fans of horror and thriller genres. The movie is available in HD 1080p =
quality on Disney+ Hotstar[^1^] and YouTube[^2^] [^3^]. The movie has a run=
time of 2 hours and 5 minutes and is rated U/A for some violent and scary s=
cenes.</div><div><br /></div><div><br /></div><div>Arundhati Movie In Tamil=
 Hd 1080p: A Review of the Horror Thriller Starring Anushka ShettyArundhati=
 is a 2009 Tamil horror thriller movie starring Anushka Shetty, Sonu Sood, =
and Arjan Bajwa. The movie is directed by Kodi Ramakrishna and produced by =
M. Shyam Prasad Reddy. The movie is a remake of the 2009 Telugu movie of th=
e same name, which was also directed by Kodi Ramakrishna.</div><div>The mov=
ie revolves around Arundhati (Anushka Shetty), a descendant of a royal fami=
ly who visits her ancestral palace for her marriage. There, she learns that=
 she is the reincarnation of her great-grandmother Jejamma (also played by =
Anushka Shetty), who was a brave and benevolent queen who fought against a =
ruthless black magician named Pasupathi (Sonu Sood). Pasupathi had a lustfu=
l eye on Jejamma and tried to possess her, but she resisted him and sacrifi=
ced her life to trap him in a tomb. However, Pasupathi manages to escape fr=
om the tomb after many years and seeks revenge on Arundhati and her family.=
 Arundhati has to face Pasupathi and his evil forces with the help of a fri=
endly spirit named Anwar (Arjan Bajwa), who was Jejamma's lover in her prev=
ious life.</div><div>Arundhati is a movie that blends horror, action, drama=
, and romance in an engaging way. The movie has stunning visuals, impressiv=
e sets, and captivating music. The movie also showcases the rich culture an=
d traditions of Tamil Nadu, especially the folk art forms and rituals. The =
movie has won several awards, including four Filmfare Awards South and thre=
e Nandi Awards.</div><div>Arundhati Movie In Tamil Hd 1080p: Cast and Crew =
DetailsThe movie features an ensemble cast of talented actors who have deli=
vered remarkable performances. Anushka Shetty plays the dual role of Arundh=
ati and Jejamma with grace and conviction. She portrays the contrasting per=
sonalities of the modern and courageous Arundhati and the traditional and h=
eroic Jejamma with ease and elegance. She also underwent rigorous training =
in martial arts and sword fighting for the role. Sonu Sood plays the menaci=
ng villain Pasupathi with flair and intensity. He also underwent prosthetic=
 makeup for his character's look. Arjan Bajwa plays the supportive and roma=
ntic Anwar with charm and sincerity. He also dubbed his own voice for the T=
amil version of the movie.</div><div>The movie also features veteran actors=
 like Kaikala Satyanarayana, Manorama, Sayaji Shinde, Chalapathi Rao, Annap=
oorna, Ahuti Prasad, Subhashini, Prudhviraj, Bhel Prasad, Leena Sidhu, Deep=
ak, Divya Nagesh, and others in supporting roles. The movie is directed by =
Kodi Ramakrishna, who is known for his movies in fantasy and horror genres.=
 He has also directed movies like Ammoru, Devi Putrudu, Devullu, Anji, etc.=
 The movie is written by Chintapalli Ramana and Manav Mahapatra. The movie =
is produced by M. Shyam Prasad Reddy under his banner Mallemala Entertainme=
nts. He is also known for producing movies like Prema Katha Chitram, Kshana=
 Kshanam, etc.</div><div>Arundhati Movie In Tamil Hd 1080p: Technical Aspec=
tsThe movie boasts of high-quality technical aspects that enhance the viewi=
ng experience. The cinematography by K.K. Senthil Kumar is splendid and cap=
tures the grandeur of the palace, the beauty of the landscapes, and the hor=
ror of the dark scenes. The editing by Marthand K. Venkatesh is crisp and s=
mooth and maintains the pace of the movie. The music by Koti is melodious a=
nd haunting and suits the mood of the movie. The songs are sung by singers =
like Karthik, Harini, Malathi Lakshmanan, Kalpana Raghavendar, etc. The bac=
kground score by Koti is also effective and creates tension and suspense in=
 the scenes.</div><div>The visual effects by various artists are outstandin=
g and realistic and create a convincing world of magic and mystery. The vis=
ual effects supervisors are San</div><div>=C2=A035727fac0c</div><div><br />=
</div><div><br /></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/ad9097c1-d8fd-4a0f-baf0-c0f6f17f8c34n%40googlegroups.c=
om?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgi=
d/kasan-dev/ad9097c1-d8fd-4a0f-baf0-c0f6f17f8c34n%40googlegroups.com</a>.<b=
r />

------=_Part_29551_1011547699.1701121376744--

------=_Part_29550_1712330673.1701121376744--

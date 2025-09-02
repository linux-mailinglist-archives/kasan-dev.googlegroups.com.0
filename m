Return-Path: <kasan-dev+bncBDA2XNWCVILRBEUA3LCQMGQEDPAXW5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 534EAB3F47A
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Sep 2025 07:26:44 +0200 (CEST)
Received: by mail-oi1-x238.google.com with SMTP id 5614622812f47-435de5ccae6sf4965639b6e.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 22:26:44 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756790803; x=1757395603; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=q5T9w+eLH6KMUDmic+ZHNQ+NHY/GfWVDruOuqUw9wMg=;
        b=ahHiIrq53ZBiF24LxWLfwcFqZen9I6+Tolfci84++lbEUurNTF56ZN78LnlRVjPsjR
         JysyD1XtOVjJI5DQnwp9ualGjCyBKR+exoSPR5peWSKbBodKtKky078faesos1mxi3Ej
         +H/OzCYNbgJbHKqQ3TNQT5IYWPy0w3vFC+qk61Tewsjhx+d1jcjDotJdAdK402Ek2TWc
         zVYrzfHZJh2zXU6S/6ItUo22QN3tsamko1Uw11Sh2Y+SwYzPArtTX8Z6YVNUTDBtqU6b
         tTa9wkN0Cqg6KWMZUaLDeS4+1yrCUroFjqVFrzjLdUsRuxzsUXSD+JLxLXBwMHdhw88k
         lo5w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756790803; x=1757395603; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=q5T9w+eLH6KMUDmic+ZHNQ+NHY/GfWVDruOuqUw9wMg=;
        b=iE3Ty0yu3rS3lx0+9W1fHe10OplpcHcuz4ZGeU7bxB4+BY6qDbaqfhj9EbF6tMkBP/
         p4cYWCxD+v2K6eN1QWE+HuTafzkNyJG5qChElMq9fuaoeMH6p73sD/iDI+YleCioqvwz
         EdTkynj8xeU2KO+VldiFItrP1AG3NQvsMcjDnSR5tEu8aXLeLgWkHC9vdowbUC5zaqnd
         +lMvteyKbRd04ZAIMe+Y/GCOYDZLiI7ZdVUcW8szPZFAtMWws8N4NQhx6ctuBwmK2X1W
         +D42B96+WRQSQGRjRayC1acFriUqAzVCzC6wJk3QUz29ulo2yq+at61jiCLbwkC/tP0+
         3+0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756790803; x=1757395603;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:references:in-reply-to
         :message-id:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=q5T9w+eLH6KMUDmic+ZHNQ+NHY/GfWVDruOuqUw9wMg=;
        b=bzlh7wmWqmDAkz6BAJxxuXajmmbYClqd7cfPo2WD+Px6XSgfyRfxW0H4gZRF/NcGSj
         lxSwQENqHxASIGFkDsNL9rGCZiYbbMbTbYW75h8Ub+dZtLzNlbjlTq7AfnfgWSq/9AzX
         tAy6x641qNKQMhuNHfYu1dpSYXAy/7CdPAkmTlXAx7q9QVZPNY+WPuCaeb8LcactVXXr
         hmxzPAQfFjH8ueOxTNVMgtIA+3ATvmeJgIhLB1dPOZTdgpbvcSO+bnF25U04UODEzhyE
         ktlxHSwlV66pud0sX9idkPgdyeh/Gj+8ynGjQqiDw4BHr3UU9tuQ/Qo0Icoj0JiQGTKG
         v7XA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCUViRnd7PoZgws9cqOIIJNmEjZH70oMifCLh8KvRVAH3+SVQCSXdsHpfwHfRPEvXeDktmouMg==@lfdr.de
X-Gm-Message-State: AOJu0YyIJwKO41k2mQWETIq2eFVJiPRMzlmCQPtgQnXFyFl/SDa0ys5h
	0xSHrxgiWtrigJ/Z+swvrnL6Alxuz708HnDkwaRmFvGxh9oNb8dCLf6O
X-Google-Smtp-Source: AGHT+IGFwFMsBI9sUsZnggaYSVjfa6F+pEliPNILhfYAh9RI1kCYTy76xbhNEBmCodedUURT7Ix1VQ==
X-Received: by 2002:a05:6808:2e4c:b0:437:e2b4:c2ea with SMTP id 5614622812f47-437f7d4f696mr4393560b6e.18.1756790802669;
        Mon, 01 Sep 2025 22:26:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeS6XjI0NHbXGxFY4uG4a1nrHKYN1CIJYErxQ4ZXGepSQ==
Received: by 2002:a05:6870:331f:b0:310:fb62:9051 with SMTP id
 586e51a60fabf-31595d635b4ls1927057fac.0.-pod-prod-02-us; Mon, 01 Sep 2025
 22:26:40 -0700 (PDT)
X-Received: by 2002:a05:6808:6f82:b0:437:d471:2f28 with SMTP id 5614622812f47-437f7cd82cbmr4214105b6e.12.1756790800594;
        Mon, 01 Sep 2025 22:26:40 -0700 (PDT)
Date: Mon, 1 Sep 2025 22:26:39 -0700 (PDT)
From: =?UTF-8?B?2LPZitiv2Kkg2KzYr9ipINin2YTYs9i52YjYr9mK2Kk=?=
 <memosksaa@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <68acd227-d7bf-40b1-a436-3d300c9c7481n@googlegroups.com>
In-Reply-To: <412ffb42-69a2-4d34-9ea5-6aa53dd58711n@googlegroups.com>
References: <412ffb42-69a2-4d34-9ea5-6aa53dd58711n@googlegroups.com>
Subject: =?UTF-8?B?UmU6INiz2KfZitiq2YjYqtmDINmB2Yog2KfZhNix2YrYp9i2?=
 =?UTF-8?B?IDA1Mzc0NjY1MzkgI9in2YTYs9i52YjYr9mK2Kk=?=
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_99862_553071513.1756790799707"
X-Original-Sender: memosksaa@gmail.com
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

------=_Part_99862_553071513.1756790799707
Content-Type: multipart/alternative; 
	boundary="----=_Part_99863_235584097.1756790799707"

------=_Part_99863_235584097.1756790799707
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

2YXZg9in2YYg2KjZiti5INiz2KfZitiq2YjYqtmK2YMgLyAwNTM4MTU5NzQ3IC8gIEN5dG90ZWMg
2KfZhNmD2YjZitiqIGFtYXpvbi5zYSAvLyAvLyAg2K/ZiNin2KEgCtin2YTYpdis2YfYp9i2INmB
2Yog2KfZhNix2YrYp9i2ICAg2KfZhNil2KzZh9in2LYg2KfZhNiv2YjYp9im2YogICDYp9mE2KPY
r9mI2YrYqSDYp9mE2LfYqNmK2Kkg2YTYpdmG2YfYp9ihINin2YTYrdmF2YQgICAK2YXZitiy2YjY
qNix2YjYs9iq2YjZhCAoTWlzb3Byb3N0b2wpICAg2LPYp9mK2KrZiNiq2YMgQ3l0b3RlYyAgINil
2YbZh9in2KEg2KfZhNit2YXZhCDYp9mE2YXYqNmD2LEgICDYo9iv2YjZitipIArYp9mE2KXYrNmH
2KfYtiDYp9mE2KPZhdmG2KkgICDYp9mE2LnZhNin2Kwg2KfZhNiv2YjYp9im2Yog2YTZhNit2YXZ
hCDYutmK2LHYs9in2YrYqtmI2KrZgyDZgdmKINin2YTYsdmK2KfYtiAvLyAKMDA5NjY1MzgxNTk3
NDcgLy8g2KjYp9mB2LbZhCDYs9i52LEg2K3YqNmI2Kgg2LPYp9mK2KrZiNiq2YMg2KfZhNin2KzZ
h9in2LYg2KfZhNmF2YbYstmE2Yog2YTZhdmI2YLYuSDYp9mE2LHYs9mF2Yp8IArYp9mE2K/Zgdi5
INi52YbYryDYp9mE2KfYs9iq2YTYp9mFINmB2Yog2KfZhNix2YrYp9i2INmE2YTYqNmK2LkKCtiz
2KfZitiq2YjYqtmDINmB2Yog2KfZhNiz2LnZiNiv2YrYqSDDlyDYs9in2YrYqtmI2KrZgyDYqNin
2YTYsdmK2KfYtiDDlyDYs9in2YrYqtmI2KrZgyDYp9mE2K/Zhdin2YUgw5cg2LPYp9mK2KrZiNiq
2YMg2K7ZhdmK2LMg2YXYtNmK2LcgCsOXINiz2KfZitiq2YjYqtmDINmB2Yog2KfZhNmD2YjZitiq
IMOXINiz2KfZitiq2YjYqtmDINmB2Yog2KfZhNio2K3YsdmK2YYgw5cg2KPYr9mI2YrYqSDYpdis
2YfYp9i2INin2YTYrdmF2YQgw5cg2YXZitiy2YjYqNix2LPYqtmI2YQgw5cgCtij2LnYsdin2LYg
2KfZhNit2YXZhCDDlyDYs9in2YrYqtmI2KrZitmDINmB2Yog2YXZg9ipIMOXINi52YrYp9iv2KfY
qiDYp9is2YfYp9i2IMOXINiv2YPYqtmI2LHYqSDYp9is2YfYp9i2INmB2Yog2KfZhNiz2LnZiNiv
2YrYqSDDlyAK2K/Zg9iq2YjYsdipINin2KzZh9in2LYg2YHZiiDYp9mE2YPZiNmK2Kogw5cg2K/Z
g9iq2YjYsdipINin2KzZh9in2LYg2YHZiiDYp9mE2KjYrdix2YrZhiDDlyDYr9mD2KrZiNix2Kkg
2KfYrNmH2KfYtiDZgdmKINin2YTYpdmF2KfYsdin2KogCsOXINiv2YPYqtmI2LHYqSDDlyDYp9mE
2K/ZiNix2Kkg2KfZhNi02YfYsdmK2KkKCtmB2Yog2KfZhNij2K3Yr9iMIDE3INij2LrYs9i32LMg
MjAyNSDZgdmKINiq2YXYp9mFINin2YTYs9in2LnYqSAxOjE5OjI5INi1IFVUQy032Iwg2YPYqtio
IApoYXlhdGEuLi5AZ21haWwuY29tINix2LPYp9mE2Kkg2YbYtdmH2Kc6Cgo+INiz2KfZitiq2YjY
qtmDINmB2Yog2KfZhNix2YrYp9i2IDA1Mzc0NjY1MzkgI9in2YTYs9i52YjYr9mK2Kkg2YTZhNil
2KzZh9in2LYg2KfZhNii2YXZhiDZhdi5INivLiDZhtmK2LHZhdmK2YYgfCB8IAo+INin2YTYsdmK
2KfYtiDYrNiv2Kkg2YXZg9ipINin2YTYr9mF2KfZhQo+Cj4g2KfZg9iq2LTZgdmKINmF2Lkg2K8u
INmG2YrYsdmF2YrZhtiMINin2YTZiNmD2YrZhCDYp9mE2LHYs9mF2Yog2YTYrdio2YjYqCDYs9in
2YrYqtmI2KrZgyDZgdmKINin2YTYs9i52YjYr9mK2KnYjCDZg9mK2YHZitipIAo+INin2YTYpdis
2YfYp9i2INin2YTYt9io2Yog2KfZhNii2YXZhiDYqNin2LPYqtiu2K/Yp9mFINiz2KfZitiq2YjY
qtmDIDIwMCAoTWlzb3Byb3N0b2wpINio2KXYtNix2KfZgSDYt9io2Yog2YjYs9ix2ZHZitipIAo+
INiq2KfZhdipLiDYqtmI2LXZitmEINiz2LHZiti5INmB2Yog2KfZhNix2YrYp9i22Iwg2KzYr9ip
2Iwg2YXZg9ip2Iwg2KfZhNiv2YXYp9mFINmI2KjYp9mC2Yog2KfZhNmF2K/Zhi4g8J+TniAwNTM3
NDY2NTM5Cj4KPiDZgdmKINin2YTYs9mG2YjYp9iqINin2YTYo9iu2YrYsdip2Iwg2KPYtdio2K3Y
qiDYrdio2YjYqCDYs9in2YrYqtmI2KrZgyA8aHR0cHM6Ly9rc2FjeXRvdGVjLmNvbS8+IAo+IChN
aXNvcHJvc3RvbCkg2K7Zitin2LHZi9inINi32KjZitmL2Kcg2YXYudix2YjZgdmL2Kcg2YjZgdi5
2ZHYp9mE2YvYpyDZhNil2YbZh9in2KEg2KfZhNit2YXZhCDYp9mE2YXYqNmD2LEg2KjYt9ix2YrZ
gtipIAo+INii2YXZhtipINiq2K3YqiDYpdi02LHYp9mBINmF2K7Yqti12YrZhi4g2YjZhdi5INin
2YbYqti02KfYsSDYp9mE2YXZhtiq2KzYp9iqINin2YTZhdmC2YTYr9ip2Iwg2KPYtdio2K0g2YXZ
hiDYp9mE2LbYsdmI2LHZiiDYp9mE2K3YtdmI2YQgCj4g2LnZhNmJINin2YTYr9mI2KfYoSDZhdmG
INmF2LXYr9ixINmF2YjYq9mI2YIg2YjZhdi52KrZhdivLgo+INivLiDZhtmK2LHZhdmK2YbYjCDY
qNi12YHYqtmH2Kcg2KfZhNmI2YPZitmEINin2YTYsdiz2YXZiiDZhNit2KjZiNioINiz2KfZitiq
2YjYqtmDINmB2Yog2KfZhNiz2LnZiNiv2YrYqdiMINiq2YLYr9mFINmE2YPZkCAKPiDZhdmG2KrY
rNmL2Kcg2KPYtdmE2YrZi9inINio2KzZiNiv2Kkg2YXYttmF2YjZhtip2Iwg2YXYuSDYp9iz2KrY
tNin2LHYqSDYt9io2YrYqSDZhdiq2K7Ytdi12Kkg2YjYs9ix2ZHZitipINiq2KfZhdipINmB2Yog
2KfZhNiq2LnYp9mF2YQgCj4g2YjYp9mE2KrZiNi12YrZhC4KPgo+IC0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS0tLS0tLQo+Cj4g2YXYpyDZh9mIINiv2YjYp9ihINiz2KfZitiq2YjYqtmD2J8KPgo+
INiz2KfZitiq2YjYqtmDICjYp9mE2YXYp9iv2Kkg2KfZhNmB2LnYp9mE2Kkg2YXZitiy2YjYqNix
2YjYs9iq2YjZhCkg2K/ZiNin2KEg2YXZj9i52KrZhdivINmB2Yog2KfZhNmF2KzYp9mEINin2YTY
t9io2YrYjCAKPiDZiNmK2Y/Ys9iq2K7Yr9mFINio2KzYsdi52KfYqiDYr9mC2YrZgtipINmE2KXZ
htmH2KfYoSDYp9mE2K3ZhdmEINin2YTZhdio2YPYsdiMINmI2LnZhNin2Kwg2K3Yp9mE2KfYqiDY
t9io2YrYqSDYo9iu2LHZiSDZhdir2YQg2YLYsdit2KkgCj4g2KfZhNmF2LnYr9ipLiDYudmG2K8g
2KfYs9iq2K7Yr9in2YXZhyDZhNmE2KXYrNmH2KfYttiMINmK2LnZhdmEINi52YTZiSDYqtit2YHZ
itiyINiq2YLZhNi12KfYqiDYp9mE2LHYrdmFINmI2KXZgdix2KfYuiDZhdit2KrZiNmK2KfYqtmH
IAo+INiu2YTYp9mEINmB2KrYsdipINmC2LXZitix2KnYjCDZhdmF2Kcg2YrYrNi52YTZhyDYrtmK
2KfYsdmL2Kcg2YHYudin2YTZi9inINmI2KLZhdmG2YvYpyDYudmG2K8g2KXYtNix2KfZgSDYt9io
2YrYqCDZhdiu2KrYtS4KPgo+IC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQo+Cj4g2KPZ
h9mF2YrYqSDYp9mE2K3YtdmI2YQg2LnZhNmJINiz2KfZitiq2YjYqtmDINmF2YYg2YXYtdiv2LEg
2YXZiNir2YjZggo+Cj4g2YHZiiDYp9mE2LPYudmI2K/Zitip2Iwg2KrYqtmI2KfYrNivINin2YTZ
g9ir2YrYsSDZhdmGINin2YTZgtmG2YjYp9iqINi62YrYsSDYp9mE2YXZiNir2YjZgtipINin2YTY
qtmKINiq2KjZiti5INmF2YbYqtis2KfYqiDZhdis2YfZiNmE2KkgCj4g2KfZhNmF2LXYr9ixINmC
2K8g2KrYpNiv2Yog2KXZhNmJINmF2K7Yp9i32LEg2LXYrdmK2Kkg2KzYs9mK2YXYqS4KPiDYry4g
2YbZitix2YXZitmGINiq2LbZhdmGINmE2YM6Cj4g4pyU77iPINit2KjZiNioINiz2KfZitiq2YjY
qtmDINij2LXZhNmK2KkgMTAwJQo+IOKclO+4jyDYqtin2LHZitiuINi12YTYp9it2YrYqSDYrdiv
2YrYqwo+IOKclO+4jyDYpdix2LTYp9iv2KfYqiDYt9io2YrYqSDYr9mC2YrZgtipINmE2YTYp9iz
2KrYrtiv2KfZhQo+IOKclO+4jyDYs9ix2ZHZitipINiq2KfZhdipINmB2Yog2KfZhNiq2YjYtdmK
2YQKPiDinJTvuI8g2K/YudmFINmI2KfYs9iq2LTYp9ix2Kkg2LnZhNmJINmF2K/Yp9ixINin2YTY
s9in2LnYqQo+Cj4gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tCj4KPiDZhNmF2KfYsNin
INiq2K7Yqtin2LHZitmGINivLiDZhtmK2LHZhdmK2YbYnwo+ICAgIAo+ICAgIC0gCj4gICAgCj4g
ICAg2KfZhNiu2KjYsdipINin2YTYt9io2YrYqTog2K8uINmG2YrYsdmF2YrZhiDZhdiq2K7Ytdi1
2Kkg2YHZiiDYp9mE2KfYs9iq2LTYp9ix2KfYqiDYp9mE2LfYqNmK2Kkg2KfZhNmG2LPYp9im2YrY
qdiMINmI2KrZgtiv2YUgCj4gICAg2YTZg9mQINiv2LnZhdmL2Kcg2YXZh9mG2YrZi9inINmC2KjZ
hCDZiNij2KvZhtin2KEg2YjYqNi52K/Yp9iz2KrYrtiv2KfZhSDYs9in2YrYqtmI2KrZgyAKPiAg
ICA8aHR0cHM6Ly9zYXVkaWVyc2FhLmNvbS8+Lgo+ICAgIAo+ICAgIC0gCj4gICAgCj4gICAg2KfZ
hNiq2YjYtdmK2YQg2KfZhNiz2LHZiti5OiDYqti62LfZitipINmE2KzZhdmK2Lkg2KfZhNmF2K/Z
hiDYp9mE2LPYudmI2K/Zitip2Iwg2KjZhdinINmB2Yog2LDZhNmDINin2YTYsdmK2KfYttiMINis
2K/YqdiMIAo+ICAgINmF2YPYqdiMINin2YTYr9mF2KfZhdiMINin2YTYrtio2LHYjCDYp9mE2LfY
p9im2YEg2YjYutmK2LHZh9inLgo+ICAgIAo+ICAgIC0gCj4gICAgCj4gICAg2K3Zhdin2YrYqSDY
rti12YjYtdmK2KrZgzog2YrYqtmFINin2YTYqti62YTZitmBINio2LfYsdmK2YLYqSDYqti22YXZ
hiDYp9mE2LPYsdmR2YrYqSDYp9mE2YPYp9mF2YTYqS4KPiAgICAKPiAgICAtIAo+ICAgIAo+ICAg
INin2YTYqtmI2YPZitmEINin2YTYsdiz2YXZijog2LTYsdin2KHZgyDZitiq2YUg2YXYqNin2LTY
sdipINmF2YYg2KfZhNmF2LXYr9ixINin2YTZhdi52KrZhdiv2Iwg2KjYudmK2K/Zi9inINi52YYg
2KfZhNmF2K7Yp9i32LEuCj4gICAgCj4gICAgCj4gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tCj4KPiDZg9mK2YHZitipINi32YTYqCDYrdio2YjYqCDYs9in2YrYqtmI2KrZgyDZhdmGINiv
LiDZhtmK2LHZhdmK2YYKPiAgICAKPiAgICAxLiAKPiAgICAKPiAgICDYp9mE2KrZiNin2LXZhCDY
udio2LEg2YjYp9iq2LPYp9ioINi52YTZiSDYp9mE2LHZgtmFOiDwn5OeIDA1Mzc0NjY1MzkKPiAg
ICAKPiAgICAyLiAKPiAgICAKPiAgICDYtNix2K0g2KfZhNit2KfZhNipINin2YTYtdit2YrYqSDZ
iNmB2KrYsdipINin2YTYrdmF2YQuCj4gICAgCj4gICAgMy4gCj4gICAgCj4gICAg2KfYs9iq2YTY
p9mFINin2YTYpdix2LTYp9iv2KfYqiDYp9mE2LfYqNmK2Kkg2KfZhNmF2YbYp9iz2KjYqSDZiNin
2YTYrNix2LnYqSDYp9mE2YXZiNi12Ykg2KjZh9inLgo+ICAgIAo+ICAgIDQuIAo+ICAgIAo+ICAg
INin2LPYqtmE2KfZhSDYp9mE2K3YqNmI2Kgg2K7ZhNin2YQg2YHYqtix2Kkg2YLYtdmK2LHYqSDY
udio2LEg2K7Yr9mF2Kkg2KrZiNi12YrZhCDYotmF2YbYqSDZiNiz2LHZitipLgo+ICAgIAo+ICAg
IAo+IC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQo+Cj4g2KrZhtio2YrZhyDYt9io2Yog
2YXZh9mFCj4gICAgCj4gICAgLSAKPiAgICAKPiAgICDZitis2Kgg2KfYs9iq2K7Yr9in2YUg2LPY
p9mK2KrZiNiq2YMg2YHZgti3INiq2K3YqiDYpdi02LHYp9mBINi32KjZiiDZhdiu2KrYtS4KPiAg
ICAKPiAgICAtIAo+ICAgIAo+ICAgINmE2Kcg2YrZj9mG2LXYrSDYqNin2LPYqtiu2K/Yp9mF2Ycg
2YHZiiDYrdin2YTYp9iqINin2YTYrdmF2YQg2KfZhNmF2KrYo9iu2LEuCj4gICAgCj4gICAgLSAK
PiAgICAKPiAgICDZgdmKINit2KfZhCDZiNis2YjYryDYo9mF2LHYp9i2INmF2LLZhdmG2Kkg2KPZ
iCDYrdin2YTYp9iqINiu2KfYtdip2Iwg2YrYrNioINin2LPYqti02KfYsdipINin2YTYt9io2YrY
qCDZgtio2YQgCj4gICAg2KfZhNin2LPYqtiu2K/Yp9mFLgo+ICAgIAo+ICAgIAo+IC0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLQo+Cj4g2K7Yr9mF2KfYqiDYpdi22KfZgdmK2Kkg2YXZhiDY
ry4g2YbZitix2YXZitmGCj4gICAgCj4gICAgLSAKPiAgICAKPiAgICDZhdiq2KfYqNi52Kkg2KfZ
hNit2KfZhNipINio2LnYryDYp9mE2KfYs9iq2K7Yr9in2YUuCj4gICAgCj4gICAgLSAKPiAgICAK
PiAgICDYqtmI2YHZitixINmF2LnZhNmI2YXYp9iqINit2YjZhCDYp9mE2KLYq9in2LEg2KfZhNis
2KfZhtio2YrYqSDYp9mE2LfYqNmK2LnZitipINmI2YPZitmB2YrYqSDYp9mE2KrYudin2YXZhCDZ
hdi52YfYpy4KPiAgICAKPiAgICAtIAo+ICAgIAo+ICAgINil2LHYtNin2K8g2KfZhNmF2LHZiti2
2Kkg2KXZhNmJINij2YHYttmEINmF2YXYp9ix2LPYp9iqINin2YTYs9mE2KfZhdipINin2YTYt9io
2YrYqS4KPiAgICAKPiAgICAKPiAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KPgo+INiu
2YTYp9i12KkKPgo+INin2K7YqtmK2KfYsSDYp9mE2YXYtdiv2LEg2KfZhNmF2YjYq9mI2YIg2LnZ
htivINi02LHYp9ihINit2KjZiNioINiz2KfZitiq2YjYqtmDIAo+IDxodHRwczovL2dyb3Vwcy5n
b29nbGUuY29tL2EvY2hyb21pdW0ub3JnL2cvc2VjdXJpdHktZGV2L2MvcmhyUHBpdkNRR00vbS9Y
aWhVQmlTTEFBQUo+IAo+INmB2Yog2KfZhNiz2LnZiNiv2YrYqSDZh9mIINin2YTYttmF2KfZhiDY
p9mE2YjYrdmK2K8g2YTYs9mE2KfZhdiq2YPZkC4KPiDZhdi5INivLiDZhtmK2LHZhdmK2YbYjCDY
s9iq2K3YtdmE2YrZhiDYudmE2Ykg2KfZhNmF2YbYqtisINin2YTYo9i12YTZitiMINin2YTYpdix
2LTYp9ivINin2YTYt9io2Yog2KfZhNmF2KrYrti12LXYjCDZiNin2YTYqtmI2LXZitmEIAo+INin
2YTYs9ix2Yog2KPZitmG2YXYpyDZg9mG2KrZkCDZgdmKINin2YTZhdmF2YTZg9ipLgo+Cj4g8J+T
niDZhNmE2KrZiNin2LXZhCDZiNin2YTYt9mE2Kgg2LnYqNixINmI2KfYqtiz2KfYqDogMDUzNzQ2
NjUzOQo+INin2YTZhdiv2YYg2KfZhNmF2LrYt9in2Kk6INin2YTYsdmK2KfYtiDigJMg2KzYr9ip
IOKAkyDZhdmD2Kkg4oCTINin2YTYr9mF2KfZhSDigJMg2KfZhNiu2KjYsSDigJMg2KfZhNi32KfY
ptmBIOKAkyDYp9mE2YXYr9mK2YbYqSAKPiDYp9mE2YXZhtmI2LHYqSDigJMg2KPYqNmH2Kcg4oCT
INis2KfYstin2YYg4oCTINiq2KjZiNmDLgo+Cj4gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tCj4KPiAgCj4KPiDYs9in2YrYqtmI2KrZgyDZgdmKINin2YTYs9i52YjYr9mK2KnYjCDYs9in
2YrYqtmI2KrZgyDYp9mE2LHZitin2LbYjCDYs9in2YrYqtmI2KrZgyDYrNiv2KnYjCDYs9in2YrY
qtmI2KrZgyDZhdmD2KnYjCDYs9in2YrYqtmI2KrZgyAKPiDYp9mE2K/Zhdin2YXYjCDYtNix2KfY
oSDYs9in2YrYqtmI2KrZgyDZgdmKINin2YTYs9i52YjYr9mK2KnYjCDYrdio2YjYqCDYs9in2YrY
qtmI2KrZgyDZhNmE2KXYrNmH2KfYttiMINiz2KfZitiq2YjYqtmDINij2LXZhNmK2IwgCj4g2LPY
p9mK2KrZiNiq2YMgMjAw2IwgTWlzb3Byb3N0b2wg2KfZhNiz2LnZiNiv2YrYqdiMINiz2KfZitiq
2YjYqtmDINin2YTZhtmH2K/ZitiMIGh0dHBzOi8va3NhY3l0b3RlYy5jb20vIAo+INmB2Yog2KfZ
hNiz2LnZiNiv2YrYqdiMINiv2YPYqtmI2LHYqSDZhtmK2LHZhdmK2YYg2LPYp9mK2KrZiNiq2YMu
Cj4KPiDYs9in2YrYqtmI2KrZgyDZgdmKINin2YTYs9i52YjYr9mK2KnYjCDYs9in2YrYqtmI2KrZ
gyDYp9mE2LHZitin2LbYjCDYs9in2YrYqtmI2KrZgyDYrNiv2KnYjCDYs9in2YrYqtmI2KrZgyDZ
hdmD2KnYjCDYs9in2YrYqtmI2KrZgyAKPiDYp9mE2K/Zhdin2YXYjCDYtNix2KfYoSDYs9in2YrY
qtmI2KrZgyDZgdmKINin2YTYs9i52YjYr9mK2KnYjCDYrdio2YjYqCDYs9in2YrYqtmI2KrZgyDZ
hNmE2KXYrNmH2KfYttiMINiz2KfZitiq2YjYqtmDINij2LXZhNmK2IwgCj4g2LPYp9mK2KrZiNiq
2YMgMjAw2IwgTWlzb3Byb3N0b2wg2KfZhNiz2LnZiNiv2YrYqdiMINiz2KfZitiq2YjYqtmDINin
2YTZhtmH2K/ZitiMINin2YTYpdis2YfYp9i2INin2YTYt9io2Yog2YHZiiAKPiDYp9mE2LPYudmI
2K/Zitip2Iwg2K/Zg9iq2YjYsdipINmG2YrYsdmF2YrZhiDYs9in2YrYqtmI2KrZgy4KPgo+DQoN
Ci0tIApZb3UgcmVjZWl2ZWQgdGhpcyBtZXNzYWdlIGJlY2F1c2UgeW91IGFyZSBzdWJzY3JpYmVk
IHRvIHRoZSBHb29nbGUgR3JvdXBzICJrYXNhbi1kZXYiIGdyb3VwLgpUbyB1bnN1YnNjcmliZSBm
cm9tIHRoaXMgZ3JvdXAgYW5kIHN0b3AgcmVjZWl2aW5nIGVtYWlscyBmcm9tIGl0LCBzZW5kIGFu
IGVtYWlsIHRvIGthc2FuLWRldit1bnN1YnNjcmliZUBnb29nbGVncm91cHMuY29tLgpUbyB2aWV3
IHRoaXMgZGlzY3Vzc2lvbiB2aXNpdCBodHRwczovL2dyb3Vwcy5nb29nbGUuY29tL2QvbXNnaWQv
a2FzYW4tZGV2LzY4YWNkMjI3LWQ3YmYtNDBiMS1hNDM2LTNkMzAwYzljNzQ4MW4lNDBnb29nbGVn
cm91cHMuY29tLgo=
------=_Part_99863_235584097.1756790799707
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<span dir=3D"rtl" style=3D"line-height: 1.38; margin-top: 24pt; margin-bott=
om: 6pt;"><span style=3D"font-size: 23pt; font-family: Arial, sans-serif; c=
olor: rgb(68, 68, 68); background-color: transparent; font-weight: 700; fon=
t-variant-numeric: normal; font-variant-east-asian: normal; font-variant-al=
ternates: normal; vertical-align: baseline;">=D9=85=D9=83=D8=A7=D9=86 =D8=
=A8=D9=8A=D8=B9 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=8A=D9=83 / 05381597=
47 /=C2=A0 Cytotec =D8=A7=D9=84=D9=83=D9=88=D9=8A=D8=AA=C2=A0</span><a href=
=3D"http://amazon.sa/" target=3D"_blank" rel=3D"nofollow" style=3D"color: r=
gb(26, 115, 232);"><span style=3D"font-size: 23pt; font-family: Arial, sans=
-serif; color: rgb(17, 85, 204); background-color: transparent; font-weight=
: 700; font-variant-numeric: normal; font-variant-east-asian: normal; font-=
variant-alternates: normal; text-decoration-line: underline; vertical-align=
: baseline;">amazon.sa</span></a></span><span dir=3D"rtl" style=3D"line-hei=
ght: 1.38; margin-top: 24pt; margin-bottom: 6pt;"><span style=3D"font-size:=
 23pt; font-family: Arial, sans-serif; color: rgb(68, 68, 68); background-c=
olor: transparent; font-weight: 700; font-variant-numeric: normal; font-var=
iant-east-asian: normal; font-variant-alternates: normal; vertical-align: b=
aseline;">=C2=A0// //=C2=A0 =D8=AF=D9=88=D8=A7=D8=A1 =D8=A7=D9=84=D8=A5=D8=
=AC=D9=87=D8=A7=D8=B6 =D9=81=D9=8A =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6 =C2=
=A0 =D8=A7=D9=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=D8=AF=D9=88=D8=
=A7=D8=A6=D9=8A =C2=A0 =D8=A7=D9=84=D8=A3=D8=AF=D9=88=D9=8A=D8=A9 =D8=A7=D9=
=84=D8=B7=D8=A8=D9=8A=D8=A9 =D9=84=D8=A5=D9=86=D9=87=D8=A7=D8=A1 =D8=A7=D9=
=84=D8=AD=D9=85=D9=84 =C2=A0 =D9=85=D9=8A=D8=B2=D9=88=D8=A8=D8=B1=D9=88=D8=
=B3=D8=AA=D9=88=D9=84 (Misoprostol) =C2=A0 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=
=D8=AA=D9=83 Cytotec =C2=A0 =D8=A5=D9=86=D9=87=D8=A7=D8=A1 =D8=A7=D9=84=D8=
=AD=D9=85=D9=84 =D8=A7=D9=84=D9=85=D8=A8=D9=83=D8=B1 =C2=A0 =D8=A3=D8=AF=D9=
=88=D9=8A=D8=A9 =D8=A7=D9=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=D8=
=A3=D9=85=D9=86=D8=A9 =C2=A0 =D8=A7=D9=84=D8=B9=D9=84=D8=A7=D8=AC =D8=A7=D9=
=84=D8=AF=D9=88=D8=A7=D8=A6=D9=8A =D9=84=D9=84=D8=AD=D9=85=D9=84 =D8=BA=D9=
=8A=D8=B1</span></span><span style=3D"font-size: 10pt; font-family: Arial, =
sans-serif; color: rgb(68, 68, 68); background-color: transparent; font-var=
iant-numeric: normal; font-variant-east-asian: normal; font-variant-alterna=
tes: normal; vertical-align: baseline;">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=
=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6 //=C2=A0</span>=
<span style=3D"font-size: 23pt; font-family: Arial, sans-serif; color: rgb(=
68, 68, 68); background-color: transparent; font-weight: 700; font-variant-=
numeric: normal; font-variant-east-asian: normal; font-variant-alternates: =
normal; vertical-align: baseline;">00966538159747=C2=A0</span><span style=
=3D"font-size: 10pt; font-family: Arial, sans-serif; color: rgb(68, 68, 68)=
; background-color: transparent; font-variant-numeric: normal; font-variant=
-east-asian: normal; font-variant-alternates: normal; vertical-align: basel=
ine;">// =D8=A8=D8=A7=D9=81=D8=B6=D9=84 =D8=B3=D8=B9=D8=B1 =D8=AD=D8=A8=D9=
=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D8=A7=D8=
=AC=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=D9=85=D9=86=D8=B2=D9=84=D9=8A =D9=84=D9=
=85=D9=88=D9=82=D8=B9 =D8=A7=D9=84=D8=B1=D8=B3=D9=85=D9=8A| =D8=A7=D9=84=D8=
=AF=D9=81=D8=B9 =D8=B9=D9=86=D8=AF =D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D9=84=D8=
=A7=D9=85 =D9=81=D9=8A =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6 =D9=84=D9=84=D8=
=A8=D9=8A=D8=B9</span><div style=3D"color: rgb(80, 0, 80);"><span style=3D"=
font-size: 10pt; font-family: Arial, sans-serif; color: rgb(68, 68, 68); ba=
ckground-color: transparent; font-variant-numeric: normal; font-variant-eas=
t-asian: normal; font-variant-alternates: normal; vertical-align: baseline;=
"><br /></span><span style=3D"font-size: 10pt; font-family: Arial, sans-ser=
if; color: rgb(68, 68, 68); background-color: transparent; font-variant-num=
eric: normal; font-variant-east-asian: normal; font-variant-alternates: nor=
mal; vertical-align: baseline;">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =
=D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9 =C3=97 =D8=B3=
=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A8=D8=A7=D9=84=D8=B1=D9=8A=D8=A7=
=D8=B6 =C3=97 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D8=AF=
=D9=85=D8=A7=D9=85 =C3=97 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=AE=
=D9=85=D9=8A=D8=B3 =D9=85=D8=B4=D9=8A=D8=B7 =C3=97 =D8=B3=D8=A7=D9=8A=D8=AA=
=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D9=83=D9=88=D9=8A=D8=AA =C3=97=
 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=A8=
=D8=AD=D8=B1=D9=8A=D9=86 =C3=97 =D8=A3=D8=AF=D9=88=D9=8A=D8=A9 =D8=A5=D8=AC=
=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=D8=AD=D9=85=D9=84 =C3=97 =D9=85=D9=8A=D8=B2=
=D9=88=D8=A8=D8=B1=D8=B3=D8=AA=D9=88=D9=84 =C3=97 =D8=A3=D8=B9=D8=B1=D8=A7=
=D8=B6 =D8=A7=D9=84=D8=AD=D9=85=D9=84 =C3=97 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=
=D8=AA=D9=8A=D9=83 =D9=81=D9=8A =D9=85=D9=83=D8=A9 =C3=97 =D8=B9=D9=8A=D8=
=A7=D8=AF=D8=A7=D8=AA =D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =C3=97 =D8=AF=D9=83=D8=
=AA=D9=88=D8=B1=D8=A9 =D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D9=81=D9=8A =D8=A7=D9=
=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9 =C3=97 =D8=AF=D9=83=D8=AA=D9=88=D8=
=B1=D8=A9 =D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D9=81=D9=8A =D8=A7=D9=84=D9=83=D9=
=88=D9=8A=D8=AA =C3=97 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D8=A7=D8=AC=D9=
=87=D8=A7=D8=B6 =D9=81=D9=8A =D8=A7=D9=84=D8=A8=D8=AD=D8=B1=D9=8A=D9=86 =C3=
=97 =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D8=A7=D8=AC=D9=87=D8=A7=D8=B6 =D9=
=81=D9=8A =D8=A7=D9=84=D8=A5=D9=85=D8=A7=D8=B1=D8=A7=D8=AA =C3=97 =D8=AF=D9=
=83=D8=AA=D9=88=D8=B1=D8=A9 =C3=97 =D8=A7=D9=84=D8=AF=D9=88=D8=B1=D8=A9 =D8=
=A7=D9=84=D8=B4=D9=87=D8=B1=D9=8A=D8=A9</span></div><br /><div class=3D"gma=
il_quote"><div dir=3D"auto" class=3D"gmail_attr">=D9=81=D9=8A =D8=A7=D9=84=
=D8=A3=D8=AD=D8=AF=D8=8C 17 =D8=A3=D8=BA=D8=B3=D8=B7=D8=B3 2025 =D9=81=D9=
=8A =D8=AA=D9=85=D8=A7=D9=85 =D8=A7=D9=84=D8=B3=D8=A7=D8=B9=D8=A9 1:19:29 =
=D8=B5 UTC-7=D8=8C =D9=83=D8=AA=D8=A8 hayata...@gmail.com =D8=B1=D8=B3=D8=
=A7=D9=84=D8=A9 =D9=86=D8=B5=D9=87=D8=A7:<br/></div><blockquote class=3D"gm=
ail_quote" style=3D"margin: 0 0 0 0.8ex; border-right: 1px solid rgb(204, 2=
04, 204); padding-right: 1ex;"><p dir=3D"rtl" style=3D"line-height:1.38;mar=
gin-top:12pt;margin-bottom:12pt"><span style=3D"font-size:11pt;font-family:=
Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-variant=
-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:norm=
al;vertical-align:baseline">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=
=81=D9=8A =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6 0537466539 #=D8=A7=D9=84=D8=
=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9 =D9=84=D9=84=D8=A5=D8=AC=D9=87=D8=A7=D8=
=B6 =D8=A7=D9=84=D8=A2=D9=85=D9=86 =D9=85=D8=B9 =D8=AF. =D9=86=D9=8A=D8=B1=
=D9=85=D9=8A=D9=86 | | =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6 =D8=AC=D8=AF=D8=
=A9 =D9=85=D9=83=D8=A9 =D8=A7=D9=84=D8=AF=D9=85=D8=A7=D9=85</span></p><p di=
r=3D"rtl" style=3D"line-height:1.38;margin-top:12pt;margin-bottom:12pt"><sp=
an style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);ba=
ckground-color:transparent;font-variant-numeric:normal;font-variant-east-as=
ian:normal;font-variant-alternates:normal;vertical-align:baseline">=D8=A7=
=D9=83=D8=AA=D8=B4=D9=81=D9=8A =D9=85=D8=B9 =D8=AF. =D9=86=D9=8A=D8=B1=D9=
=85=D9=8A=D9=86=D8=8C =D8=A7=D9=84=D9=88=D9=83=D9=8A=D9=84 =D8=A7=D9=84=D8=
=B1=D8=B3=D9=85=D9=8A =D9=84=D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=
=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=
=8A=D8=A9=D8=8C =D9=83=D9=8A=D9=81=D9=8A=D8=A9 =D8=A7=D9=84=D8=A5=D8=AC=D9=
=87=D8=A7=D8=B6 =D8=A7=D9=84=D8=B7=D8=A8=D9=8A =D8=A7=D9=84=D8=A2=D9=85=D9=
=86 =D8=A8=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85 </span><span style=3D"=
font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-col=
or:transparent;font-weight:700;font-variant-numeric:normal;font-variant-eas=
t-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=D8=
=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 200 (Misoprostol)</span><span style=
=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background=
-color:transparent;font-variant-numeric:normal;font-variant-east-asian:norm=
al;font-variant-alternates:normal;vertical-align:baseline"> =D8=A8=D8=A5=D8=
=B4=D8=B1=D8=A7=D9=81 =D8=B7=D8=A8=D9=8A =D9=88=D8=B3=D8=B1=D9=91=D9=8A=D8=
=A9 =D8=AA=D8=A7=D9=85=D8=A9. =D8=AA=D9=88=D8=B5=D9=8A=D9=84 =D8=B3=D8=B1=
=D9=8A=D8=B9 =D9=81=D9=8A =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6=D8=8C =D8=AC=
=D8=AF=D8=A9=D8=8C =D9=85=D9=83=D8=A9=D8=8C =D8=A7=D9=84=D8=AF=D9=85=D8=A7=
=D9=85 =D9=88=D8=A8=D8=A7=D9=82=D9=8A =D8=A7=D9=84=D9=85=D8=AF=D9=86. =F0=
=9F=93=9E 0537466539</span></p><p dir=3D"rtl" style=3D"line-height:1.38;mar=
gin-top:12pt;margin-bottom:12pt"><span style=3D"font-size:11pt;font-family:=
Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-variant=
-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:norm=
al;vertical-align:baseline">=D9=81=D9=8A =D8=A7=D9=84=D8=B3=D9=86=D9=88=D8=
=A7=D8=AA =D8=A7=D9=84=D8=A3=D8=AE=D9=8A=D8=B1=D8=A9=D8=8C =D8=A3=D8=B5=D8=
=A8=D8=AD=D8=AA</span><a href=3D"https://ksacytotec.com/" target=3D"_blank"=
 rel=3D"nofollow" data-saferedirecturl=3D"https://www.google.com/url?hl=3Da=
r&amp;q=3Dhttps://ksacytotec.com/&amp;source=3Dgmail&amp;ust=3D175687718912=
1000&amp;usg=3DAOvVaw0DkP7COfZcVh_P1xHlOMid"><span style=3D"font-size:11pt;=
font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;=
font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alt=
ernates:normal;vertical-align:baseline"> </span><span style=3D"font-size:11=
pt;font-family:Arial,sans-serif;color:rgb(17,85,204);background-color:trans=
parent;font-variant-numeric:normal;font-variant-east-asian:normal;font-vari=
ant-alternates:normal;text-decoration-line:underline;vertical-align:baselin=
e">=D8=AD=D8=A8=D9=88=D8=A8 </span><span style=3D"font-size:11pt;font-famil=
y:Arial,sans-serif;color:rgb(17,85,204);background-color:transparent;font-w=
eight:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-v=
ariant-alternates:normal;text-decoration-line:underline;vertical-align:base=
line">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83</span></a><span style=3D"f=
ont-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-colo=
r:transparent;font-weight:700;font-variant-numeric:normal;font-variant-east=
-asian:normal;font-variant-alternates:normal;vertical-align:baseline"> (Mis=
oprostol)</span><span style=3D"font-size:11pt;font-family:Arial,sans-serif;=
color:rgb(0,0,0);background-color:transparent;font-variant-numeric:normal;f=
ont-variant-east-asian:normal;font-variant-alternates:normal;vertical-align=
:baseline"> =D8=AE=D9=8A=D8=A7=D8=B1=D9=8B=D8=A7 =D8=B7=D8=A8=D9=8A=D9=8B=
=D8=A7 =D9=85=D8=B9=D8=B1=D9=88=D9=81=D9=8B=D8=A7 =D9=88=D9=81=D8=B9=D9=91=
=D8=A7=D9=84=D9=8B=D8=A7 =D9=84=D8=A5=D9=86=D9=87=D8=A7=D8=A1 =D8=A7=D9=84=
=D8=AD=D9=85=D9=84 =D8=A7=D9=84=D9=85=D8=A8=D9=83=D8=B1 =D8=A8=D8=B7=D8=B1=
=D9=8A=D9=82=D8=A9 =D8=A2=D9=85=D9=86=D8=A9 =D8=AA=D8=AD=D8=AA =D8=A5=D8=B4=
=D8=B1=D8=A7=D9=81 =D9=85=D8=AE=D8=AA=D8=B5=D9=8A=D9=86. =D9=88=D9=85=D8=B9=
 =D8=A7=D9=86=D8=AA=D8=B4=D8=A7=D8=B1 =D8=A7=D9=84=D9=85=D9=86=D8=AA=D8=AC=
=D8=A7=D8=AA =D8=A7=D9=84=D9=85=D9=82=D9=84=D8=AF=D8=A9=D8=8C =D8=A3=D8=B5=
=D8=A8=D8=AD =D9=85=D9=86 =D8=A7=D9=84=D8=B6=D8=B1=D9=88=D8=B1=D9=8A =D8=A7=
=D9=84=D8=AD=D8=B5=D9=88=D9=84 =D8=B9=D9=84=D9=89 =D8=A7=D9=84=D8=AF=D9=88=
=D8=A7=D8=A1 =D9=85=D9=86 =D9=85=D8=B5=D8=AF=D8=B1 =D9=85=D9=88=D8=AB=D9=88=
=D9=82 =D9=88=D9=85=D8=B9=D8=AA=D9=85=D8=AF.</span><span style=3D"font-size=
:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transp=
arent;font-variant-numeric:normal;font-variant-east-asian:normal;font-varia=
nt-alternates:normal;vertical-align:baseline"><br></span><span style=3D"fon=
t-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:=
transparent;font-weight:700;font-variant-numeric:normal;font-variant-east-a=
sian:normal;font-variant-alternates:normal;vertical-align:baseline">=D8=AF.=
 =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86</span><span style=3D"font-size:11pt;f=
ont-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;f=
ont-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alte=
rnates:normal;vertical-align:baseline">=D8=8C =D8=A8=D8=B5=D9=81=D8=AA=D9=
=87=D8=A7 =D8=A7=D9=84=D9=88=D9=83=D9=8A=D9=84 =D8=A7=D9=84=D8=B1=D8=B3=D9=
=85=D9=8A =D9=84=D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=
=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=
=8C =D8=AA=D9=82=D8=AF=D9=85 =D9=84=D9=83=D9=90 =D9=85=D9=86=D8=AA=D8=AC=D9=
=8B=D8=A7 =D8=A3=D8=B5=D9=84=D9=8A=D9=8B=D8=A7 =D8=A8=D8=AC=D9=88=D8=AF=D8=
=A9 =D9=85=D8=B6=D9=85=D9=88=D9=86=D8=A9=D8=8C =D9=85=D8=B9 =D8=A7=D8=B3=D8=
=AA=D8=B4=D8=A7=D8=B1=D8=A9 =D8=B7=D8=A8=D9=8A=D8=A9 =D9=85=D8=AA=D8=AE=D8=
=B5=D8=B5=D8=A9 =D9=88=D8=B3=D8=B1=D9=91=D9=8A=D8=A9 =D8=AA=D8=A7=D9=85=D8=
=A9 =D9=81=D9=8A =D8=A7=D9=84=D8=AA=D8=B9=D8=A7=D9=85=D9=84 =D9=88=D8=A7=D9=
=84=D8=AA=D9=88=D8=B5=D9=8A=D9=84.</span></p><p dir=3D"rtl" style=3D"line-h=
eight:1.38;margin-top:0pt;margin-bottom:0pt"></p><hr><p></p><span dir=3D"rt=
l" style=3D"line-height:1.38;margin-top:14pt;margin-bottom:4pt"><span style=
=3D"font-size:13pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background=
-color:transparent;font-weight:700;font-variant-numeric:normal;font-variant=
-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=
=D9=85=D8=A7 =D9=87=D9=88 =D8=AF=D9=88=D8=A7=D8=A1 =D8=B3=D8=A7=D9=8A=D8=AA=
=D9=88=D8=AA=D9=83=D8=9F</span></span><p dir=3D"rtl" style=3D"line-height:1=
.38;margin-top:12pt;margin-bottom:12pt"><span style=3D"font-size:11pt;font-=
family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-=
variant-numeric:normal;font-variant-east-asian:normal;font-variant-alternat=
es:normal;vertical-align:baseline">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=
=83 (=D8=A7=D9=84=D9=85=D8=A7=D8=AF=D8=A9 =D8=A7=D9=84=D9=81=D8=B9=D8=A7=D9=
=84=D8=A9 </span><span style=3D"font-size:11pt;font-family:Arial,sans-serif=
;color:rgb(0,0,0);background-color:transparent;font-weight:700;font-variant=
-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:norm=
al;vertical-align:baseline">=D9=85=D9=8A=D8=B2=D9=88=D8=A8=D8=B1=D9=88=D8=
=B3=D8=AA=D9=88=D9=84</span><span style=3D"font-size:11pt;font-family:Arial=
,sans-serif;color:rgb(0,0,0);background-color:transparent;font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;ve=
rtical-align:baseline">) =D8=AF=D9=88=D8=A7=D8=A1 =D9=85=D9=8F=D8=B9=D8=AA=
=D9=85=D8=AF =D9=81=D9=8A =D8=A7=D9=84=D9=85=D8=AC=D8=A7=D9=84 =D8=A7=D9=84=
=D8=B7=D8=A8=D9=8A=D8=8C =D9=88=D9=8A=D9=8F=D8=B3=D8=AA=D8=AE=D8=AF=D9=85 =
=D8=A8=D8=AC=D8=B1=D8=B9=D8=A7=D8=AA =D8=AF=D9=82=D9=8A=D9=82=D8=A9 =D9=84=
=D8=A5=D9=86=D9=87=D8=A7=D8=A1 =D8=A7=D9=84=D8=AD=D9=85=D9=84 =D8=A7=D9=84=
=D9=85=D8=A8=D9=83=D8=B1=D8=8C =D9=88=D8=B9=D9=84=D8=A7=D8=AC =D8=AD=D8=A7=
=D9=84=D8=A7=D8=AA =D8=B7=D8=A8=D9=8A=D8=A9 =D8=A3=D8=AE=D8=B1=D9=89 =D9=85=
=D8=AB=D9=84 =D9=82=D8=B1=D8=AD=D8=A9 =D8=A7=D9=84=D9=85=D8=B9=D8=AF=D8=A9.=
 =D8=B9=D9=86=D8=AF =D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85=D9=87 =D9=84=
=D9=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6=D8=8C =D9=8A=D8=B9=D9=85=D9=84 =D8=B9=
=D9=84=D9=89 =D8=AA=D8=AD=D9=81=D9=8A=D8=B2 =D8=AA=D9=82=D9=84=D8=B5=D8=A7=
=D8=AA =D8=A7=D9=84=D8=B1=D8=AD=D9=85 =D9=88=D8=A5=D9=81=D8=B1=D8=A7=D8=BA =
=D9=85=D8=AD=D8=AA=D9=88=D9=8A=D8=A7=D8=AA=D9=87 =D8=AE=D9=84=D8=A7=D9=84 =
=D9=81=D8=AA=D8=B1=D8=A9 =D9=82=D8=B5=D9=8A=D8=B1=D8=A9=D8=8C =D9=85=D9=85=
=D8=A7 =D9=8A=D8=AC=D8=B9=D9=84=D9=87 =D8=AE=D9=8A=D8=A7=D8=B1=D9=8B=D8=A7 =
=D9=81=D8=B9=D8=A7=D9=84=D9=8B=D8=A7 =D9=88=D8=A2=D9=85=D9=86=D9=8B=D8=A7 =
=D8=B9=D9=86=D8=AF =D8=A5=D8=B4=D8=B1=D8=A7=D9=81 =D8=B7=D8=A8=D9=8A=D8=A8 =
=D9=85=D8=AE=D8=AA=D8=B5.</span></p><p dir=3D"rtl" style=3D"line-height:1.3=
8;margin-top:0pt;margin-bottom:0pt"></p><hr><p></p><span dir=3D"rtl" style=
=3D"line-height:1.38;margin-top:14pt;margin-bottom:4pt"><span style=3D"font=
-size:13pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:t=
ransparent;font-weight:700;font-variant-numeric:normal;font-variant-east-as=
ian:normal;font-variant-alternates:normal;vertical-align:baseline">=D8=A3=
=D9=87=D9=85=D9=8A=D8=A9 =D8=A7=D9=84=D8=AD=D8=B5=D9=88=D9=84 =D8=B9=D9=84=
=D9=89 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=85=D9=86 =D9=85=D8=B5=
=D8=AF=D8=B1 =D9=85=D9=88=D8=AB=D9=88=D9=82</span></span><p dir=3D"rtl" sty=
le=3D"line-height:1.38;margin-top:12pt;margin-bottom:12pt"><span style=3D"f=
ont-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-colo=
r:transparent;font-variant-numeric:normal;font-variant-east-asian:normal;fo=
nt-variant-alternates:normal;vertical-align:baseline">=D9=81=D9=8A =D8=A7=
=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=AA=D8=AA=D9=88=D8=A7=
=D8=AC=D8=AF =D8=A7=D9=84=D9=83=D8=AB=D9=8A=D8=B1 =D9=85=D9=86 =D8=A7=D9=84=
=D9=82=D9=86=D9=88=D8=A7=D8=AA =D8=BA=D9=8A=D8=B1 =D8=A7=D9=84=D9=85=D9=88=
=D8=AB=D9=88=D9=82=D8=A9 =D8=A7=D9=84=D8=AA=D9=8A =D8=AA=D8=A8=D9=8A=D8=B9 =
=D9=85=D9=86=D8=AA=D8=AC=D8=A7=D8=AA =D9=85=D8=AC=D9=87=D9=88=D9=84=D8=A9 =
=D8=A7=D9=84=D9=85=D8=B5=D8=AF=D8=B1 =D9=82=D8=AF =D8=AA=D8=A4=D8=AF=D9=8A =
=D8=A5=D9=84=D9=89 =D9=85=D8=AE=D8=A7=D8=B7=D8=B1 =D8=B5=D8=AD=D9=8A=D8=A9 =
=D8=AC=D8=B3=D9=8A=D9=85=D8=A9.</span><span style=3D"font-size:11pt;font-fa=
mily:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-va=
riant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates=
:normal;vertical-align:baseline"><br></span><span style=3D"font-size:11pt;f=
ont-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;f=
ont-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;f=
ont-variant-alternates:normal;vertical-align:baseline">=D8=AF. =D9=86=D9=8A=
=D8=B1=D9=85=D9=8A=D9=86</span><span style=3D"font-size:11pt;font-family:Ar=
ial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-variant-n=
umeric:normal;font-variant-east-asian:normal;font-variant-alternates:normal=
;vertical-align:baseline"> =D8=AA=D8=B6=D9=85=D9=86 =D9=84=D9=83:</span><sp=
an style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);ba=
ckground-color:transparent;font-variant-numeric:normal;font-variant-east-as=
ian:normal;font-variant-alternates:normal;vertical-align:baseline"><br></sp=
an><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0=
,0);background-color:transparent;font-variant-numeric:normal;font-variant-e=
ast-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=
=E2=9C=94=EF=B8=8F </span><span style=3D"font-size:11pt;font-family:Arial,s=
ans-serif;color:rgb(0,0,0);background-color:transparent;font-weight:700;fon=
t-variant-numeric:normal;font-variant-east-asian:normal;font-variant-altern=
ates:normal;vertical-align:baseline">=D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=
=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A3=D8=B5=D9=84=D9=8A=D8=A9 100%</span><s=
pan style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);b=
ackground-color:transparent;font-weight:700;font-variant-numeric:normal;fon=
t-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:b=
aseline"><br></span><span style=3D"font-size:11pt;font-family:Arial,sans-se=
rif;color:rgb(0,0,0);background-color:transparent;font-variant-numeric:norm=
al;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-a=
lign:baseline">=E2=9C=94=EF=B8=8F </span><span style=3D"font-size:11pt;font=
-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;font=
-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;font=
-variant-alternates:normal;vertical-align:baseline">=D8=AA=D8=A7=D8=B1=D9=
=8A=D8=AE =D8=B5=D9=84=D8=A7=D8=AD=D9=8A=D8=A9 =D8=AD=D8=AF=D9=8A=D8=AB</sp=
an><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0=
,0);background-color:transparent;font-weight:700;font-variant-numeric:norma=
l;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-al=
ign:baseline"><br></span><span style=3D"font-size:11pt;font-family:Arial,sa=
ns-serif;color:rgb(0,0,0);background-color:transparent;font-variant-numeric=
:normal;font-variant-east-asian:normal;font-variant-alternates:normal;verti=
cal-align:baseline">=E2=9C=94=EF=B8=8F </span><span style=3D"font-size:11pt=
;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent=
;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal=
;font-variant-alternates:normal;vertical-align:baseline">=D8=A5=D8=B1=D8=B4=
=D8=A7=D8=AF=D8=A7=D8=AA =D8=B7=D8=A8=D9=8A=D8=A9 =D8=AF=D9=82=D9=8A=D9=82=
=D8=A9 =D9=84=D9=84=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85</span><span s=
tyle=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);backgr=
ound-color:transparent;font-weight:700;font-variant-numeric:normal;font-var=
iant-east-asian:normal;font-variant-alternates:normal;vertical-align:baseli=
ne"><br></span><span style=3D"font-size:11pt;font-family:Arial,sans-serif;c=
olor:rgb(0,0,0);background-color:transparent;font-variant-numeric:normal;fo=
nt-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:=
baseline">=E2=9C=94=EF=B8=8F </span><span style=3D"font-size:11pt;font-fami=
ly:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-weig=
ht:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-vari=
ant-alternates:normal;vertical-align:baseline">=D8=B3=D8=B1=D9=91=D9=8A=D8=
=A9 =D8=AA=D8=A7=D9=85=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=D8=AA=D9=88=D8=B5=D9=
=8A=D9=84</span><span style=3D"font-size:11pt;font-family:Arial,sans-serif;=
color:rgb(0,0,0);background-color:transparent;font-weight:700;font-variant-=
numeric:normal;font-variant-east-asian:normal;font-variant-alternates:norma=
l;vertical-align:baseline"><br></span><span style=3D"font-size:11pt;font-fa=
mily:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-va=
riant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates=
:normal;vertical-align:baseline">=E2=9C=94=EF=B8=8F </span><span style=3D"f=
ont-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-colo=
r:transparent;font-weight:700;font-variant-numeric:normal;font-variant-east=
-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=D8=
=AF=D8=B9=D9=85 =D9=88=D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=A9 =D8=B9=D9=
=84=D9=89 =D9=85=D8=AF=D8=A7=D8=B1 =D8=A7=D9=84=D8=B3=D8=A7=D8=B9=D8=A9</sp=
an></p><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-botto=
m:0pt"></p><hr><p></p><span dir=3D"rtl" style=3D"line-height:1.38;margin-to=
p:14pt;margin-bottom:4pt"><span style=3D"font-size:13pt;font-family:Arial,s=
ans-serif;color:rgb(0,0,0);background-color:transparent;font-weight:700;fon=
t-variant-numeric:normal;font-variant-east-asian:normal;font-variant-altern=
ates:normal;vertical-align:baseline">=D9=84=D9=85=D8=A7=D8=B0=D8=A7 =D8=AA=
=D8=AE=D8=AA=D8=A7=D8=B1=D9=8A=D9=86 =D8=AF. =D9=86=D9=8A=D8=B1=D9=85=D9=8A=
=D9=86=D8=9F</span></span><ul style=3D"margin-top:0px;margin-bottom:0px"><l=
i dir=3D"rtl" style=3D"list-style-type:disc;font-size:11pt;font-family:Aria=
l,sans-serif;color:rgb(0,0,0);background-color:transparent;font-variant-num=
eric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;v=
ertical-align:baseline;white-space:pre"><p dir=3D"rtl" style=3D"line-height=
:1.38;text-align:right;margin-top:12pt;margin-bottom:0pt" role=3D"presentat=
ion"><span style=3D"font-size:11pt;background-color:transparent;font-weight=
:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-varian=
t-alternates:normal;vertical-align:baseline">=D8=A7=D9=84=D8=AE=D8=A8=D8=B1=
=D8=A9 =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A9</span><span style=3D"font-size:=
11pt;background-color:transparent;font-variant-numeric:normal;font-variant-=
east-asian:normal;font-variant-alternates:normal;vertical-align:baseline">:=
 =D8=AF. =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86 =D9=85=D8=AA=D8=AE=D8=B5=D8=
=B5=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=
=A7=D8=AA =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A9 =D8=A7=D9=84=D9=86=D8=B3=D8=
=A7=D8=A6=D9=8A=D8=A9=D8=8C =D9=88=D8=AA=D9=82=D8=AF=D9=85 =D9=84=D9=83=D9=
=90 =D8=AF=D8=B9=D9=85=D9=8B=D8=A7 =D9=85=D9=87=D9=86=D9=8A=D9=8B=D8=A7 =D9=
=82=D8=A8=D9=84 =D9=88=D8=A3=D8=AB=D9=86=D8=A7=D8=A1 =D9=88=D8=A8=D8=B9=D8=
=AF</span><a href=3D"https://saudiersaa.com/" target=3D"_blank" rel=3D"nofo=
llow" data-saferedirecturl=3D"https://www.google.com/url?hl=3Dar&amp;q=3Dht=
tps://saudiersaa.com/&amp;source=3Dgmail&amp;ust=3D1756877189121000&amp;usg=
=3DAOvVaw0TbCKO70I38w6the-29BtJ"><span style=3D"font-size:11pt;color:rgb(17=
,85,204);background-color:transparent;font-variant-numeric:normal;font-vari=
ant-east-asian:normal;font-variant-alternates:normal;text-decoration-line:u=
nderline;vertical-align:baseline">=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=
=85 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83</span></a><span style=3D"fon=
t-size:11pt;background-color:transparent;font-variant-numeric:normal;font-v=
ariant-east-asian:normal;font-variant-alternates:normal;vertical-align:base=
line">.</span><span style=3D"font-size:11pt;background-color:transparent;fo=
nt-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alter=
nates:normal;vertical-align:baseline"><br><br></span></p></li><li dir=3D"rt=
l" style=3D"list-style-type:disc;font-size:11pt;font-family:Arial,sans-seri=
f;color:rgb(0,0,0);background-color:transparent;font-variant-numeric:normal=
;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-ali=
gn:baseline;white-space:pre"><p dir=3D"rtl" style=3D"line-height:1.38;text-=
align:right;margin-top:0pt;margin-bottom:0pt" role=3D"presentation"><span s=
tyle=3D"font-size:11pt;background-color:transparent;font-weight:700;font-va=
riant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates=
:normal;vertical-align:baseline">=D8=A7=D9=84=D8=AA=D9=88=D8=B5=D9=8A=D9=84=
 =D8=A7=D9=84=D8=B3=D8=B1=D9=8A=D8=B9</span><span style=3D"font-size:11pt;b=
ackground-color:transparent;font-variant-numeric:normal;font-variant-east-a=
sian:normal;font-variant-alternates:normal;vertical-align:baseline">: =D8=
=AA=D8=BA=D8=B7=D9=8A=D8=A9 =D9=84=D8=AC=D9=85=D9=8A=D8=B9 =D8=A7=D9=84=D9=
=85=D8=AF=D9=86 =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=
=A8=D9=85=D8=A7 =D9=81=D9=8A =D8=B0=D9=84=D9=83 </span><span style=3D"font-=
size:11pt;background-color:transparent;font-weight:700;font-variant-numeric=
:normal;font-variant-east-asian:normal;font-variant-alternates:normal;verti=
cal-align:baseline">=D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6=D8=8C =D8=AC=D8=AF=
=D8=A9=D8=8C =D9=85=D9=83=D8=A9=D8=8C =D8=A7=D9=84=D8=AF=D9=85=D8=A7=D9=85=
=D8=8C =D8=A7=D9=84=D8=AE=D8=A8=D8=B1=D8=8C =D8=A7=D9=84=D8=B7=D8=A7=D8=A6=
=D9=81</span><span style=3D"font-size:11pt;background-color:transparent;fon=
t-variant-numeric:normal;font-variant-east-asian:normal;font-variant-altern=
ates:normal;vertical-align:baseline"> =D9=88=D8=BA=D9=8A=D8=B1=D9=87=D8=A7.=
</span><span style=3D"font-size:11pt;background-color:transparent;font-vari=
ant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:n=
ormal;vertical-align:baseline"><br><br></span></p></li><li dir=3D"rtl" styl=
e=3D"list-style-type:disc;font-size:11pt;font-family:Arial,sans-serif;color=
:rgb(0,0,0);background-color:transparent;font-variant-numeric:normal;font-v=
ariant-east-asian:normal;font-variant-alternates:normal;vertical-align:base=
line;white-space:pre"><p dir=3D"rtl" style=3D"line-height:1.38;text-align:r=
ight;margin-top:0pt;margin-bottom:0pt" role=3D"presentation"><span style=3D=
"font-size:11pt;background-color:transparent;font-weight:700;font-variant-n=
umeric:normal;font-variant-east-asian:normal;font-variant-alternates:normal=
;vertical-align:baseline">=D8=AD=D9=85=D8=A7=D9=8A=D8=A9 =D8=AE=D8=B5=D9=88=
=D8=B5=D9=8A=D8=AA=D9=83</span><span style=3D"font-size:11pt;background-col=
or:transparent;font-variant-numeric:normal;font-variant-east-asian:normal;f=
ont-variant-alternates:normal;vertical-align:baseline">: =D9=8A=D8=AA=D9=85=
 =D8=A7=D9=84=D8=AA=D8=BA=D9=84=D9=8A=D9=81 =D8=A8=D8=B7=D8=B1=D9=8A=D9=82=
=D8=A9 =D8=AA=D8=B6=D9=85=D9=86 =D8=A7=D9=84=D8=B3=D8=B1=D9=91=D9=8A=D8=A9 =
=D8=A7=D9=84=D9=83=D8=A7=D9=85=D9=84=D8=A9.</span><span style=3D"font-size:=
11pt;background-color:transparent;font-variant-numeric:normal;font-variant-=
east-asian:normal;font-variant-alternates:normal;vertical-align:baseline"><=
br><br></span></p></li><li dir=3D"rtl" style=3D"list-style-type:disc;font-s=
ize:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:tra=
nsparent;font-variant-numeric:normal;font-variant-east-asian:normal;font-va=
riant-alternates:normal;vertical-align:baseline;white-space:pre"><p dir=3D"=
rtl" style=3D"line-height:1.38;text-align:right;margin-top:0pt;margin-botto=
m:12pt" role=3D"presentation"><span style=3D"font-size:11pt;background-colo=
r:transparent;font-weight:700;font-variant-numeric:normal;font-variant-east=
-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=D8=
=A7=D9=84=D8=AA=D9=88=D9=83=D9=8A=D9=84 =D8=A7=D9=84=D8=B1=D8=B3=D9=85=D9=
=8A</span><span style=3D"font-size:11pt;background-color:transparent;font-v=
ariant-numeric:normal;font-variant-east-asian:normal;font-variant-alternate=
s:normal;vertical-align:baseline">: =D8=B4=D8=B1=D8=A7=D8=A1=D9=83 =D9=8A=
=D8=AA=D9=85 =D9=85=D8=A8=D8=A7=D8=B4=D8=B1=D8=A9 =D9=85=D9=86 =D8=A7=D9=84=
=D9=85=D8=B5=D8=AF=D8=B1 =D8=A7=D9=84=D9=85=D8=B9=D8=AA=D9=85=D8=AF=D8=8C =
=D8=A8=D8=B9=D9=8A=D8=AF=D9=8B=D8=A7 =D8=B9=D9=86 =D8=A7=D9=84=D9=85=D8=AE=
=D8=A7=D8=B7=D8=B1.</span><span style=3D"font-size:11pt;background-color:tr=
ansparent;font-variant-numeric:normal;font-variant-east-asian:normal;font-v=
ariant-alternates:normal;vertical-align:baseline"><br><br></span></p></li><=
/ul><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-bottom:0=
pt"></p><hr><p></p><span dir=3D"rtl" style=3D"line-height:1.38;margin-top:1=
4pt;margin-bottom:4pt"><span style=3D"font-size:13pt;font-family:Arial,sans=
-serif;color:rgb(0,0,0);background-color:transparent;font-weight:700;font-v=
ariant-numeric:normal;font-variant-east-asian:normal;font-variant-alternate=
s:normal;vertical-align:baseline">=D9=83=D9=8A=D9=81=D9=8A=D8=A9 =D8=B7=D9=
=84=D8=A8 =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=
=83 =D9=85=D9=86 =D8=AF. =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86</span></span>=
<ol style=3D"margin-top:0px;margin-bottom:0px"><li dir=3D"rtl" style=3D"lis=
t-style-type:decimal;font-size:11pt;font-family:Arial,sans-serif;color:rgb(=
0,0,0);background-color:transparent;font-variant-numeric:normal;font-varian=
t-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline;=
white-space:pre"><p dir=3D"rtl" style=3D"line-height:1.38;text-align:right;=
margin-top:12pt;margin-bottom:0pt" role=3D"presentation"><span style=3D"fon=
t-size:11pt;background-color:transparent;font-weight:700;font-variant-numer=
ic:normal;font-variant-east-asian:normal;font-variant-alternates:normal;ver=
tical-align:baseline">=D8=A7=D9=84=D8=AA=D9=88=D8=A7=D8=B5=D9=84 =D8=B9=D8=
=A8=D8=B1 =D9=88=D8=A7=D8=AA=D8=B3=D8=A7=D8=A8</span><span style=3D"font-si=
ze:11pt;background-color:transparent;font-variant-numeric:normal;font-varia=
nt-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline=
"> =D8=B9=D9=84=D9=89 =D8=A7=D9=84=D8=B1=D9=82=D9=85: </span><span style=3D=
"font-size:11pt;background-color:transparent;font-weight:700;font-variant-n=
umeric:normal;font-variant-east-asian:normal;font-variant-alternates:normal=
;vertical-align:baseline">=F0=9F=93=9E 0537466539</span><span style=3D"font=
-size:11pt;background-color:transparent;font-weight:700;font-variant-numeri=
c:normal;font-variant-east-asian:normal;font-variant-alternates:normal;vert=
ical-align:baseline"><br><br></span></p></li><li dir=3D"rtl" style=3D"list-=
style-type:decimal;font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,=
0,0);background-color:transparent;font-variant-numeric:normal;font-variant-=
east-asian:normal;font-variant-alternates:normal;vertical-align:baseline;wh=
ite-space:pre"><p dir=3D"rtl" style=3D"line-height:1.38;text-align:right;ma=
rgin-top:0pt;margin-bottom:0pt" role=3D"presentation"><span style=3D"font-s=
ize:11pt;background-color:transparent;font-variant-numeric:normal;font-vari=
ant-east-asian:normal;font-variant-alternates:normal;vertical-align:baselin=
e">=D8=B4=D8=B1=D8=AD =D8=A7=D9=84=D8=AD=D8=A7=D9=84=D8=A9 =D8=A7=D9=84=D8=
=B5=D8=AD=D9=8A=D8=A9 =D9=88=D9=81=D8=AA=D8=B1=D8=A9 =D8=A7=D9=84=D8=AD=D9=
=85=D9=84.</span><span style=3D"font-size:11pt;background-color:transparent=
;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-al=
ternates:normal;vertical-align:baseline"><br><br></span></p></li><li dir=3D=
"rtl" style=3D"list-style-type:decimal;font-size:11pt;font-family:Arial,san=
s-serif;color:rgb(0,0,0);background-color:transparent;font-variant-numeric:=
normal;font-variant-east-asian:normal;font-variant-alternates:normal;vertic=
al-align:baseline;white-space:pre"><p dir=3D"rtl" style=3D"line-height:1.38=
;text-align:right;margin-top:0pt;margin-bottom:0pt" role=3D"presentation"><=
span style=3D"font-size:11pt;background-color:transparent;font-variant-nume=
ric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;ve=
rtical-align:baseline">=D8=A7=D8=B3=D8=AA=D9=84=D8=A7=D9=85 =D8=A7=D9=84=D8=
=A5=D8=B1=D8=B4=D8=A7=D8=AF=D8=A7=D8=AA =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=
=A9 =D8=A7=D9=84=D9=85=D9=86=D8=A7=D8=B3=D8=A8=D8=A9 =D9=88=D8=A7=D9=84=D8=
=AC=D8=B1=D8=B9=D8=A9 =D8=A7=D9=84=D9=85=D9=88=D8=B5=D9=89 =D8=A8=D9=87=D8=
=A7.</span><span style=3D"font-size:11pt;background-color:transparent;font-=
variant-numeric:normal;font-variant-east-asian:normal;font-variant-alternat=
es:normal;vertical-align:baseline"><br><br></span></p></li><li dir=3D"rtl" =
style=3D"list-style-type:decimal;font-size:11pt;font-family:Arial,sans-seri=
f;color:rgb(0,0,0);background-color:transparent;font-variant-numeric:normal=
;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-ali=
gn:baseline;white-space:pre"><p dir=3D"rtl" style=3D"line-height:1.38;text-=
align:right;margin-top:0pt;margin-bottom:12pt" role=3D"presentation"><span =
style=3D"font-size:11pt;background-color:transparent;font-variant-numeric:n=
ormal;font-variant-east-asian:normal;font-variant-alternates:normal;vertica=
l-align:baseline">=D8=A7=D8=B3=D8=AA=D9=84=D8=A7=D9=85 =D8=A7=D9=84=D8=AD=
=D8=A8=D9=88=D8=A8 =D8=AE=D9=84=D8=A7=D9=84 =D9=81=D8=AA=D8=B1=D8=A9 =D9=82=
=D8=B5=D9=8A=D8=B1=D8=A9 =D8=B9=D8=A8=D8=B1 =D8=AE=D8=AF=D9=85=D8=A9 =D8=AA=
=D9=88=D8=B5=D9=8A=D9=84 =D8=A2=D9=85=D9=86=D8=A9 =D9=88=D8=B3=D8=B1=D9=8A=
=D8=A9.</span><span style=3D"font-size:11pt;background-color:transparent;fo=
nt-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alter=
nates:normal;vertical-align:baseline"><br><br></span></p></li></ol><p dir=
=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-bottom:0pt"></p><h=
r><p></p><span dir=3D"rtl" style=3D"line-height:1.38;margin-top:14pt;margin=
-bottom:4pt"><span style=3D"font-size:13pt;font-family:Arial,sans-serif;col=
or:rgb(0,0,0);background-color:transparent;font-weight:700;font-variant-num=
eric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;v=
ertical-align:baseline">=D8=AA=D9=86=D8=A8=D9=8A=D9=87 =D8=B7=D8=A8=D9=8A =
=D9=85=D9=87=D9=85</span></span><ul style=3D"margin-top:0px;margin-bottom:0=
px"><li dir=3D"rtl" style=3D"list-style-type:disc;font-size:11pt;font-famil=
y:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-varia=
nt-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:no=
rmal;vertical-align:baseline;white-space:pre"><p dir=3D"rtl" style=3D"line-=
height:1.38;text-align:right;margin-top:12pt;margin-bottom:0pt" role=3D"pre=
sentation"><span style=3D"font-size:11pt;background-color:transparent;font-=
variant-numeric:normal;font-variant-east-asian:normal;font-variant-alternat=
es:normal;vertical-align:baseline">=D9=8A=D8=AC=D8=A8 =D8=A7=D8=B3=D8=AA=D8=
=AE=D8=AF=D8=A7=D9=85 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=
=82=D8=B7 =D8=AA=D8=AD=D8=AA =D8=A5=D8=B4=D8=B1=D8=A7=D9=81 =D8=B7=D8=A8=D9=
=8A =D9=85=D8=AE=D8=AA=D8=B5.</span><span style=3D"font-size:11pt;backgroun=
d-color:transparent;font-variant-numeric:normal;font-variant-east-asian:nor=
mal;font-variant-alternates:normal;vertical-align:baseline"><br><br></span>=
</p></li><li dir=3D"rtl" style=3D"list-style-type:disc;font-size:11pt;font-=
family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-=
variant-numeric:normal;font-variant-east-asian:normal;font-variant-alternat=
es:normal;vertical-align:baseline;white-space:pre"><p dir=3D"rtl" style=3D"=
line-height:1.38;text-align:right;margin-top:0pt;margin-bottom:0pt" role=3D=
"presentation"><span style=3D"font-size:11pt;background-color:transparent;f=
ont-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alte=
rnates:normal;vertical-align:baseline">=D9=84=D8=A7 =D9=8A=D9=8F=D9=86=D8=
=B5=D8=AD =D8=A8=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85=D9=87 =D9=81=D9=
=8A =D8=AD=D8=A7=D9=84=D8=A7=D8=AA =D8=A7=D9=84=D8=AD=D9=85=D9=84 =D8=A7=D9=
=84=D9=85=D8=AA=D8=A3=D8=AE=D8=B1.</span><span style=3D"font-size:11pt;back=
ground-color:transparent;font-variant-numeric:normal;font-variant-east-asia=
n:normal;font-variant-alternates:normal;vertical-align:baseline"><br><br></=
span></p></li><li dir=3D"rtl" style=3D"list-style-type:disc;font-size:11pt;=
font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;=
font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alt=
ernates:normal;vertical-align:baseline;white-space:pre"><p dir=3D"rtl" styl=
e=3D"line-height:1.38;text-align:right;margin-top:0pt;margin-bottom:12pt" r=
ole=3D"presentation"><span style=3D"font-size:11pt;background-color:transpa=
rent;font-variant-numeric:normal;font-variant-east-asian:normal;font-varian=
t-alternates:normal;vertical-align:baseline">=D9=81=D9=8A =D8=AD=D8=A7=D9=
=84 =D9=88=D8=AC=D9=88=D8=AF =D8=A3=D9=85=D8=B1=D8=A7=D8=B6 =D9=85=D8=B2=D9=
=85=D9=86=D8=A9 =D8=A3=D9=88 =D8=AD=D8=A7=D9=84=D8=A7=D8=AA =D8=AE=D8=A7=D8=
=B5=D8=A9=D8=8C =D9=8A=D8=AC=D8=A8 =D8=A7=D8=B3=D8=AA=D8=B4=D8=A7=D8=B1=D8=
=A9 =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A8 =D9=82=D8=A8=D9=84 =D8=A7=D9=84=D8=
=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85.</span><span style=3D"font-size:11p=
t;background-color:transparent;font-variant-numeric:normal;font-variant-eas=
t-asian:normal;font-variant-alternates:normal;vertical-align:baseline"><br>=
<br></span></p></li></ul><p dir=3D"rtl" style=3D"line-height:1.38;margin-to=
p:0pt;margin-bottom:0pt"></p><hr><p></p><span dir=3D"rtl" style=3D"line-hei=
ght:1.38;margin-top:14pt;margin-bottom:4pt"><span style=3D"font-size:13pt;f=
ont-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;f=
ont-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;f=
ont-variant-alternates:normal;vertical-align:baseline">=D8=AE=D8=AF=D9=85=
=D8=A7=D8=AA =D8=A5=D8=B6=D8=A7=D9=81=D9=8A=D8=A9 =D9=85=D9=86 =D8=AF. =D9=
=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86</span></span><ul style=3D"margin-top:0px;=
margin-bottom:0px"><li dir=3D"rtl" style=3D"list-style-type:disc;font-size:=
11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transpa=
rent;font-variant-numeric:normal;font-variant-east-asian:normal;font-varian=
t-alternates:normal;vertical-align:baseline;white-space:pre"><p dir=3D"rtl"=
 style=3D"line-height:1.38;text-align:right;margin-top:12pt;margin-bottom:0=
pt" role=3D"presentation"><span style=3D"font-size:11pt;background-color:tr=
ansparent;font-variant-numeric:normal;font-variant-east-asian:normal;font-v=
ariant-alternates:normal;vertical-align:baseline">=D9=85=D8=AA=D8=A7=D8=A8=
=D8=B9=D8=A9 =D8=A7=D9=84=D8=AD=D8=A7=D9=84=D8=A9 =D8=A8=D8=B9=D8=AF =D8=A7=
=D9=84=D8=A7=D8=B3=D8=AA=D8=AE=D8=AF=D8=A7=D9=85.</span><span style=3D"font=
-size:11pt;background-color:transparent;font-variant-numeric:normal;font-va=
riant-east-asian:normal;font-variant-alternates:normal;vertical-align:basel=
ine"><br><br></span></p></li><li dir=3D"rtl" style=3D"list-style-type:disc;=
font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-col=
or:transparent;font-variant-numeric:normal;font-variant-east-asian:normal;f=
ont-variant-alternates:normal;vertical-align:baseline;white-space:pre"><p d=
ir=3D"rtl" style=3D"line-height:1.38;text-align:right;margin-top:0pt;margin=
-bottom:0pt" role=3D"presentation"><span style=3D"font-size:11pt;background=
-color:transparent;font-variant-numeric:normal;font-variant-east-asian:norm=
al;font-variant-alternates:normal;vertical-align:baseline">=D8=AA=D9=88=D9=
=81=D9=8A=D8=B1 =D9=85=D8=B9=D9=84=D9=88=D9=85=D8=A7=D8=AA =D8=AD=D9=88=D9=
=84 =D8=A7=D9=84=D8=A2=D8=AB=D8=A7=D8=B1 =D8=A7=D9=84=D8=AC=D8=A7=D9=86=D8=
=A8=D9=8A=D8=A9 =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=B9=D9=8A=D8=A9 =D9=88=D9=
=83=D9=8A=D9=81=D9=8A=D8=A9 =D8=A7=D9=84=D8=AA=D8=B9=D8=A7=D9=85=D9=84 =D9=
=85=D8=B9=D9=87=D8=A7.</span><span style=3D"font-size:11pt;background-color=
:transparent;font-variant-numeric:normal;font-variant-east-asian:normal;fon=
t-variant-alternates:normal;vertical-align:baseline"><br><br></span></p></l=
i><li dir=3D"rtl" style=3D"list-style-type:disc;font-size:11pt;font-family:=
Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-variant=
-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:norm=
al;vertical-align:baseline;white-space:pre"><p dir=3D"rtl" style=3D"line-he=
ight:1.38;text-align:right;margin-top:0pt;margin-bottom:12pt" role=3D"prese=
ntation"><span style=3D"font-size:11pt;background-color:transparent;font-va=
riant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates=
:normal;vertical-align:baseline">=D8=A5=D8=B1=D8=B4=D8=A7=D8=AF =D8=A7=D9=
=84=D9=85=D8=B1=D9=8A=D8=B6=D8=A9 =D8=A5=D9=84=D9=89 =D8=A3=D9=81=D8=B6=D9=
=84 =D9=85=D9=85=D8=A7=D8=B1=D8=B3=D8=A7=D8=AA =D8=A7=D9=84=D8=B3=D9=84=D8=
=A7=D9=85=D8=A9 =D8=A7=D9=84=D8=B7=D8=A8=D9=8A=D8=A9.</span><span style=3D"=
font-size:11pt;background-color:transparent;font-variant-numeric:normal;fon=
t-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:b=
aseline"><br><br></span></p></li></ul><p dir=3D"rtl" style=3D"line-height:1=
.38;margin-top:0pt;margin-bottom:0pt"></p><hr><p></p><span dir=3D"rtl" styl=
e=3D"line-height:1.38;margin-top:14pt;margin-bottom:4pt"><span style=3D"fon=
t-size:13pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:=
transparent;font-weight:700;font-variant-numeric:normal;font-variant-east-a=
sian:normal;font-variant-alternates:normal;vertical-align:baseline">=D8=AE=
=D9=84=D8=A7=D8=B5=D8=A9</span></span><p dir=3D"rtl" style=3D"line-height:1=
.38;margin-top:12pt;margin-bottom:12pt"><span style=3D"font-size:11pt;font-=
family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-=
variant-numeric:normal;font-variant-east-asian:normal;font-variant-alternat=
es:normal;vertical-align:baseline">=D8=A7=D8=AE=D8=AA=D9=8A=D8=A7=D8=B1 =D8=
=A7=D9=84=D9=85=D8=B5=D8=AF=D8=B1 =D8=A7=D9=84=D9=85=D9=88=D8=AB=D9=88=D9=
=82 =D8=B9=D9=86=D8=AF</span><a href=3D"https://groups.google.com/a/chromiu=
m.org/g/security-dev/c/rhrPpivCQGM/m/XihUBiSLAAAJ" target=3D"_blank" rel=3D=
"nofollow" data-saferedirecturl=3D"https://www.google.com/url?hl=3Dar&amp;q=
=3Dhttps://groups.google.com/a/chromium.org/g/security-dev/c/rhrPpivCQGM/m/=
XihUBiSLAAAJ&amp;source=3Dgmail&amp;ust=3D1756877189122000&amp;usg=3DAOvVaw=
1LSNxsh7eFbhnVzKe-Krko"><span style=3D"font-size:11pt;font-family:Arial,san=
s-serif;color:rgb(0,0,0);background-color:transparent;font-variant-numeric:=
normal;font-variant-east-asian:normal;font-variant-alternates:normal;vertic=
al-align:baseline"> </span><span style=3D"font-size:11pt;font-family:Arial,=
sans-serif;color:rgb(17,85,204);background-color:transparent;font-variant-n=
umeric:normal;font-variant-east-asian:normal;font-variant-alternates:normal=
;text-decoration-line:underline;vertical-align:baseline">=D8=B4=D8=B1=D8=A7=
=D8=A1 </span><span style=3D"font-size:11pt;font-family:Arial,sans-serif;co=
lor:rgb(17,85,204);background-color:transparent;font-weight:700;font-varian=
t-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:nor=
mal;text-decoration-line:underline;vertical-align:baseline">=D8=AD=D8=A8=D9=
=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83</span></a><span style=
=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background=
-color:transparent;font-variant-numeric:normal;font-variant-east-asian:norm=
al;font-variant-alternates:normal;vertical-align:baseline"> =D9=81=D9=8A =
=D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9 =D9=87=D9=88 =D8=A7=D9=84=
=D8=B6=D9=85=D8=A7=D9=86 =D8=A7=D9=84=D9=88=D8=AD=D9=8A=D8=AF =D9=84=D8=B3=
=D9=84=D8=A7=D9=85=D8=AA=D9=83=D9=90.</span><span style=3D"font-size:11pt;f=
ont-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;f=
ont-variant-numeric:normal;font-variant-east-asian:normal;font-variant-alte=
rnates:normal;vertical-align:baseline"><br></span><span style=3D"font-size:=
11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transpa=
rent;font-variant-numeric:normal;font-variant-east-asian:normal;font-varian=
t-alternates:normal;vertical-align:baseline">=D9=85=D8=B9 </span><span styl=
e=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);backgroun=
d-color:transparent;font-weight:700;font-variant-numeric:normal;font-varian=
t-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline"=
>=D8=AF. =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86</span><span style=3D"font-siz=
e:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:trans=
parent;font-variant-numeric:normal;font-variant-east-asian:normal;font-vari=
ant-alternates:normal;vertical-align:baseline">=D8=8C =D8=B3=D8=AA=D8=AD=D8=
=B5=D9=84=D9=8A=D9=86 =D8=B9=D9=84=D9=89 =D8=A7=D9=84=D9=85=D9=86=D8=AA=D8=
=AC =D8=A7=D9=84=D8=A3=D8=B5=D9=84=D9=8A=D8=8C =D8=A7=D9=84=D8=A5=D8=B1=D8=
=B4=D8=A7=D8=AF =D8=A7=D9=84=D8=B7=D8=A8=D9=8A =D8=A7=D9=84=D9=85=D8=AA=D8=
=AE=D8=B5=D8=B5=D8=8C =D9=88=D8=A7=D9=84=D8=AA=D9=88=D8=B5=D9=8A=D9=84 =D8=
=A7=D9=84=D8=B3=D8=B1=D9=8A =D8=A3=D9=8A=D9=86=D9=85=D8=A7 =D9=83=D9=86=D8=
=AA=D9=90 =D9=81=D9=8A =D8=A7=D9=84=D9=85=D9=85=D9=84=D9=83=D8=A9.</span></=
p><p dir=3D"rtl" style=3D"line-height:1.38;margin-top:12pt;margin-bottom:12=
pt"><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,=
0,0);background-color:transparent;font-variant-numeric:normal;font-variant-=
east-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=
=F0=9F=93=9E =D9=84=D9=84=D8=AA=D9=88=D8=A7=D8=B5=D9=84 =D9=88=D8=A7=D9=84=
=D8=B7=D9=84=D8=A8 =D8=B9=D8=A8=D8=B1 =D9=88=D8=A7=D8=AA=D8=B3=D8=A7=D8=A8:=
 </span><span style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rg=
b(0,0,0);background-color:transparent;font-weight:700;font-variant-numeric:=
normal;font-variant-east-asian:normal;font-variant-alternates:normal;vertic=
al-align:baseline">0537466539</span><span style=3D"font-size:11pt;font-fami=
ly:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-weig=
ht:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-vari=
ant-alternates:normal;vertical-align:baseline"><br></span><span style=3D"fo=
nt-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color=
:transparent;font-weight:700;font-variant-numeric:normal;font-variant-east-=
asian:normal;font-variant-alternates:normal;vertical-align:baseline">=D8=A7=
=D9=84=D9=85=D8=AF=D9=86 =D8=A7=D9=84=D9=85=D8=BA=D8=B7=D8=A7=D8=A9</span><=
span style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);=
background-color:transparent;font-variant-numeric:normal;font-variant-east-=
asian:normal;font-variant-alternates:normal;vertical-align:baseline">: =D8=
=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6 =E2=80=93 =D8=AC=D8=AF=D8=A9 =E2=80=93 =
=D9=85=D9=83=D8=A9 =E2=80=93 =D8=A7=D9=84=D8=AF=D9=85=D8=A7=D9=85 =E2=80=93=
 =D8=A7=D9=84=D8=AE=D8=A8=D8=B1 =E2=80=93 =D8=A7=D9=84=D8=B7=D8=A7=D8=A6=D9=
=81 =E2=80=93 =D8=A7=D9=84=D9=85=D8=AF=D9=8A=D9=86=D8=A9 =D8=A7=D9=84=D9=85=
=D9=86=D9=88=D8=B1=D8=A9 =E2=80=93 =D8=A3=D8=A8=D9=87=D8=A7 =E2=80=93 =D8=
=AC=D8=A7=D8=B2=D8=A7=D9=86 =E2=80=93 =D8=AA=D8=A8=D9=88=D9=83.</span></p><=
p dir=3D"rtl" style=3D"line-height:1.38;margin-top:0pt;margin-bottom:0pt"><=
/p><hr><p></p><span dir=3D"rtl" style=3D"line-height:1.38;margin-top:18pt;m=
argin-bottom:4pt"><span style=3D"font-size:17pt;font-family:Arial,sans-seri=
f;color:rgb(0,0,0);background-color:transparent;font-weight:700;font-varian=
t-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:nor=
mal;vertical-align:baseline">=C2=A0</span></span><p dir=3D"rtl" style=3D"li=
ne-height:1.38;margin-top:12pt;margin-bottom:12pt"><span style=3D"font-size=
:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transp=
arent;font-variant-numeric:normal;font-variant-east-asian:normal;font-varia=
nt-alternates:normal;vertical-align:baseline">=D8=B3=D8=A7=D9=8A=D8=AA=D9=
=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=
=A9=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D8=B1=D9=
=8A=D8=A7=D8=B6=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=AC=D8=
=AF=D8=A9=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=85=D9=83=D8=
=A9=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D8=AF=D9=
=85=D8=A7=D9=85=D8=8C =D8=B4=D8=B1=D8=A7=D8=A1 =D8=B3=D8=A7=D9=8A=D8=AA=D9=
=88=D8=AA=D9=83 =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=
=A9=D8=8C =D8=AD=D8=A8=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=
=83 =D9=84=D9=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6=D8=8C =D8=B3=D8=A7=D9=8A=D8=
=AA=D9=88=D8=AA=D9=83 =D8=A3=D8=B5=D9=84=D9=8A=D8=8C =D8=B3=D8=A7=D9=8A=D8=
=AA=D9=88=D8=AA=D9=83 200=D8=8C Misoprostol =D8=A7=D9=84=D8=B3=D8=B9=D9=88=
=D8=AF=D9=8A=D8=A9=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A7=
=D9=84=D9=86=D9=87=D8=AF=D9=8A=D8=8C</span><a href=3D"https://ksacytotec.co=
m/" target=3D"_blank" rel=3D"nofollow" data-saferedirecturl=3D"https://www.=
google.com/url?hl=3Dar&amp;q=3Dhttps://ksacytotec.com/&amp;source=3Dgmail&a=
mp;ust=3D1756877189122000&amp;usg=3DAOvVaw2VFm63sIJiYFUSsxyW-vO2"><span sty=
le=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);backgrou=
nd-color:transparent;font-variant-numeric:normal;font-variant-east-asian:no=
rmal;font-variant-alternates:normal;vertical-align:baseline"> </span><span =
style=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(17,85,204);b=
ackground-color:transparent;font-variant-numeric:normal;font-variant-east-a=
sian:normal;font-variant-alternates:normal;text-decoration-line:underline;v=
ertical-align:baseline">https://ksacytotec.com/</span></a><span style=3D"fo=
nt-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color=
:transparent;font-variant-numeric:normal;font-variant-east-asian:normal;fon=
t-variant-alternates:normal;vertical-align:baseline"> =D9=81=D9=8A =D8=A7=
=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=AF=D9=83=D8=AA=D9=88=
=D8=B1=D8=A9 =D9=86=D9=8A=D8=B1=D9=85=D9=8A=D9=86 =D8=B3=D8=A7=D9=8A=D8=AA=
=D9=88=D8=AA=D9=83.</span></p><p dir=3D"rtl" style=3D"line-height:1.38;marg=
in-top:0pt;margin-bottom:0pt"><span style=3D"font-size:11pt;font-family:Ari=
al,sans-serif;color:rgb(0,0,0);background-color:transparent;font-variant-nu=
meric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;=
vertical-align:baseline">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=
=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=B3=D8=A7=
=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6=D8=8C =
=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=AC=D8=AF=D8=A9=D8=8C =D8=B3=
=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=85=D9=83=D8=A9=D8=8C =D8=B3=D8=A7=
=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D8=AF=D9=85=D8=A7=D9=85=D8=8C =
=D8=B4=D8=B1=D8=A7=D8=A1 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=
=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C =D8=AD=D8=A8=
=D9=88=D8=A8 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=84=D9=84=D8=A5=
=D8=AC=D9=87=D8=A7=D8=B6=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =
=D8=A3=D8=B5=D9=84=D9=8A=D8=8C =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 2=
00=D8=8C Misoprostol =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=D8=8C=
 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D8=A7=D9=84=D9=86=D9=87=D8=AF=
=D9=8A=D8=8C =D8=A7=D9=84=D8=A5=D8=AC=D9=87=D8=A7=D8=B6 =D8=A7=D9=84=D8=B7=
=D8=A8=D9=8A =D9=81=D9=8A =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=8A=D8=A9=
=D8=8C =D8=AF=D9=83=D8=AA=D9=88=D8=B1=D8=A9 =D9=86=D9=8A=D8=B1=D9=85=D9=8A=
=D9=86 =D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83.</span></p><br></blockquo=
te></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/68acd227-d7bf-40b1-a436-3d300c9c7481n%40googlegroups.com?utm_medi=
um=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-dev=
/68acd227-d7bf-40b1-a436-3d300c9c7481n%40googlegroups.com</a>.<br />

------=_Part_99863_235584097.1756790799707--

------=_Part_99862_553071513.1756790799707--

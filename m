Return-Path: <kasan-dev+bncBD37RS4LXMIRBV5MTO7AMGQE4M7XTIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C61AA4DA83
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 11:30:49 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-2fed20dd70csf5937227a91.1
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 02:30:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741084248; cv=pass;
        d=google.com; s=arc-20240605;
        b=Zw1PBwB5dhWoMfpqrOgp2dsdu6jEXxrCKMki+lZSKxE8ZPusopva6dEANxaCZx680f
         db7blUdL8CPaqgs3h5RwW6lZPR1mXSPUOetYK/YMSjk++2Doa0jKpQxihFsKd3kx8M20
         qqm68Tqpqz0RbOWiejAgR9PlFqKsg3r0aawMp5h+l9NoUwFejSRygUss8asxmwwWnAyW
         wzXjNWK3ewvdbGGFRFbLU5FkJmT9cj7sM5s1XpfRzeH2E1ZbwyjRNh34k4s1WNI3z7Fb
         863xbK7bceyalL3ammdcmbXtxnMW2b6JaSo97z/zw/ECxki55R7YWTZJmgri3Nquo0+I
         YZaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=e9AgntQ/g6SDVOjkuqVWqUbNuYnxstwnf8Lwiq1Rx5I=;
        fh=lKq8Cxl3Ak4l/mPCK5eVWVt2LrpuHXi2yUaweL39PbQ=;
        b=Nu4XxervVI96z2ZC3b/ewnGTQ5v6rT+y2jDfS7uy6Cy84jR5zWRMvAWe41KgliBwUP
         n9IVH5drfaT+AXx8EzJqUa9sxWiBrtrhX9lbLb6v57BqG63H4uTUyBcFh4rOLx3QJv8g
         hmiyPXV9s3EmiUk10hO52kCyr5kMXZdSYlUrndAuAsZSJndLnf+k2da+mV7ZU3QYqDlX
         ThTNSyOwQdC/zxE5vxBkvaTsBQkAwDo4bQsm+29qt7ldLPpfWw52KpJ5vJbd0uOtc2Hs
         nounIhlk0D/dJwMNNa75P7M7jX5tThQBt8z+FV14Tj3VbxJ4tLzEcr+l6tIDpWBtkWBZ
         SLDQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ELK5Wgpz;
       spf=pass (google.com: domain of susanwilson58jj@gmail.com designates 2607:f8b0:4864:20::b44 as permitted sender) smtp.mailfrom=susanwilson58jj@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741084248; x=1741689048; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=e9AgntQ/g6SDVOjkuqVWqUbNuYnxstwnf8Lwiq1Rx5I=;
        b=E3jh+tlI+h3JCA8t46QvnqWCN/W6o4My6s51SR4zo9ORde+h+GFG6i/vI4lwmVnY83
         Jp/jcO4lnTHckcVxiWPWslTYAMcZkU45IqPgD+wnw4VWqhuxfUaAoWPCd9t4rOizRUfj
         phcFDi10QP2cCr297pWt3QisRDSajOgrpGjfhwVz5uQL+i71BTXbcsMOGk1dcn1vFlqW
         IkT6iA1hC1tYsuLie7IMEs+Ms9TX9+5D0TogdIQoyC2CcVcJypoOrDAT5GoX2sGkiSTI
         jdLvXfnrm1S3x6q5cbZs9W9ZjngdH8+MkYYGc1LL0Uk8DJimx1llcr0LmXP/tkUwTXLj
         /yNg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1741084248; x=1741689048; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=e9AgntQ/g6SDVOjkuqVWqUbNuYnxstwnf8Lwiq1Rx5I=;
        b=UC+5ew3Okn+CYWzthgQf9dS3TQ+tngt7MGOhXftXkjhzzlwJC/kJ+aqC2ugqBngLxO
         w+FrkPJwzETNp1cx7G+yJTiiGQmhXRw1yo2d+yxpcbvF9th78Fq4ZPhXG8Xu9xIN8L7J
         WmqrCqYPasZigGDUjYcexPFnhNx9BtbpPK4YL54FBrpsT3FNzThJVYE++JNYhSzeeJKh
         NPLxEKjBtdfB6R0n1WEx1svvOdau1vN7qHxw+KmgAi64ZAvVPG58sZXskSMhR5UvPPc6
         J5iGnl1hkFsYdhF5YvIQGUFgYmLftJufqbhc9kOPe5so4mI0g34SQMDKeuLryg8tGvfH
         wyEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741084248; x=1741689048;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=e9AgntQ/g6SDVOjkuqVWqUbNuYnxstwnf8Lwiq1Rx5I=;
        b=kpVmV8g6KltyMZVhxMUb1sLatRLDG3oteUvrS4J2pTJerVH59n75dO+r/o4AoO7ULn
         7HX5xUSfVLJDpINYRP1f23eAlfbIYUnx9luFhr/m9LxQavEpbPdMS2LjAMz/xJruoOPn
         1EsBN0OunFJhbplH/gzSWperNbv74IF+L/NLkduTqJ6oNWl2f9mgckCTVSEeCoGxSJSQ
         QnW18r4fd/iT87Hr4nQcig/m8grkCkPg4AEh7iDCn49xDqnjWs7In+6qptpxfu8yjY3x
         TSUGyssa11Dofw3+R103GnsplbiIPChQLWmV/ureLNzzLqGc/kMiKlG7J7g36onID9yh
         jh+Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWhqa4cXannNYjlW/Q9dnDi06ObbcW5tvhf9OQ2psEu1h8FSYb2BZjXY7mtwhlw/LQ1PxzySQ==@lfdr.de
X-Gm-Message-State: AOJu0YzJ44JyMRc/eznBkFCBSDp0agHkSE4hQ4/i/idaJwruX7eZFKFl
	0434feH6xV1wgMKba8wSkAN/PHOir2dzaSgEtM1yTkYW8+oabvWA
X-Google-Smtp-Source: AGHT+IHeJ7FveWIomXRchH8QvxWq/euw/TDRAKx7uGuElcN2A8Yd9S54CFHdwJR2rPjPjvTAR1JIYA==
X-Received: by 2002:a17:90b:5109:b0:2ee:ee5e:42fb with SMTP id 98e67ed59e1d1-2febab5e14amr25000087a91.13.1741084247443;
        Tue, 04 Mar 2025 02:30:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHodRvtLOM0PvmgiJGfE0SNjmF8Q1bD8//nNfN0vjUNKw==
Received: by 2002:a17:90b:955:b0:2dd:58a2:6016 with SMTP id
 98e67ed59e1d1-2fe9ff5a625ls2024292a91.1.-pod-prod-09-us; Tue, 04 Mar 2025
 02:30:46 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUAKLQsxWClifZ7fIfhQVPyysYpfhwhEFd1LV2vVlXH4biWzWAUEVNwz1fBv4cWSPt14mx49dh90B8=@googlegroups.com
X-Received: by 2002:a17:90b:4983:b0:2f8:b2c:5ef3 with SMTP id 98e67ed59e1d1-2febab5e160mr28147130a91.14.1741084246212;
        Tue, 04 Mar 2025 02:30:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741084246; cv=none;
        d=google.com; s=arc-20240605;
        b=gjWl/fjiEkZDO4GrNSTb9Olc7AkW6pwIZgeabpt9ixXD/+D0Pgz5V1KWYmlebgPgof
         eeiDNM3r9R6DpNBPLOXTMhz1QaKzetJ1uxni6HxyxlrIfDLv5Vsc6FjIRlVJKXm5Ns4N
         mU9o2WJ8wVemokXpsAQomWCYHoSy3/2vGDjsk78XAzE+sJ8jPaQ5y+NR0yiAN1tBCHxq
         AN8E7QmHHTWaG4kMrD0svKn4Cxx5ENx2wrYFk0EinkTYW0rkhkaQWW2VInxpE/O1oXjm
         DcuMaMYBcJaME6wc0Wgoti4RF+TgEXsvlzCxo+M2qfFCrcAxFlFWkBjiC80r5yFcikOY
         jzgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=uUPvK61KD1Ur2GKQx7iWN1iJNOuPiQBYonPsCmNX+U8=;
        fh=PfSFEuf9VuHZqlw/JrktB2fcFZurpvq9Fjj5Mvhi7AQ=;
        b=WKNfGQLcGeCcq3Lv+B+ZCGV5yf1WAAADgT3hdbuZirokGhWLCtamd9Y8SPWQwJyn6J
         YAxpCb2S6S/l+bnEsZxa8IFihHCTjjOdPQEUVb6ZuWxhyjDw+vMQ/9Bhr49dAalz+eD4
         dovVdG5asgCfKX/ws8YEpXwaNdeONoXOl1I9FmIYc1JQTm0hrOE4YUZASXgh4oQeHgrZ
         7lf8Qc20RMKVOjeofZL/wQm00/lvtNkJmhjVZJrDD80s+6KuDLoOw61AUfRnZ4pKuxyM
         v+PHWef7AEwQRY90aHoS2TUVKuDJnDnJGVmpxVjE1ELE2l5Fv8oW9ExFtwJ3h3j1a8le
         aPVA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ELK5Wgpz;
       spf=pass (google.com: domain of susanwilson58jj@gmail.com designates 2607:f8b0:4864:20::b44 as permitted sender) smtp.mailfrom=susanwilson58jj@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yb1-xb44.google.com (mail-yb1-xb44.google.com. [2607:f8b0:4864:20::b44])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2ff359648e5si181366a91.0.2025.03.04.02.30.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Mar 2025 02:30:46 -0800 (PST)
Received-SPF: pass (google.com: domain of susanwilson58jj@gmail.com designates 2607:f8b0:4864:20::b44 as permitted sender) client-ip=2607:f8b0:4864:20::b44;
Received: by mail-yb1-xb44.google.com with SMTP id 3f1490d57ef6-e4930eca0d4so3883849276.3
        for <kasan-dev@googlegroups.com>; Tue, 04 Mar 2025 02:30:46 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV27y7f0lSwbMGY27MoQB1CT0rFJZ73zQWphyZfI4ijxhVMzAEu8jKLX/k99ZoDwvQ4rYJRORhM+UQ=@googlegroups.com
X-Gm-Gg: ASbGncsO9TYF4pv872fo5ebK2+kuZVyXjCGCJWXvialMdU4PbM3ptzrXybFY/LEYW1m
	uWC3zGUS8H0aZr4izOfA4NNAx8n9VFDCuuqPLMLOuh3jUPOURr4cIbI2DCGJ3YpkpSi9FEJCNxp
	t+EbM/VHjLZZoafL48W01NiM5EvqkklwzOcgO7+aOuyLIMOUgwUjuY4eYxHYrq
X-Received: by 2002:a05:6902:3209:b0:e58:30dc:615b with SMTP id
 3f1490d57ef6-e60b2ebd9c6mr18141822276.22.1741084245383; Tue, 04 Mar 2025
 02:30:45 -0800 (PST)
MIME-Version: 1.0
From: Susan Wilson <susanwilson58jj@gmail.com>
Date: Tue, 4 Mar 2025 17:30:34 +0700
X-Gm-Features: AQ5f1JoCE8R1wEnSNIAwTMEUaoLJ3q0HLzA1QPgPXAEl_8ifg7njgmedmNE5OHY
Message-ID: <CAMa3D0FJEmkHE7vL0DM53+qP2wUgfQxTgcxN6Jb=fc2Dp96Txw@mail.gmail.com>
Subject: =?UTF-8?B?5LiN54Sv5rC05ZCD5bCx562J5LqO4oCc5pyN5q+S4oCd77yf?=
To: 2962310475@qq.com, kasan-dev@googlegroups.com, jiaxin.han@sjtu.edu.cn, 
	yuntlo2222@cityu.edu.hk
Content-Type: multipart/alternative; boundary="000000000000f861a3062f81c392"
X-Original-Sender: susanwilson58jj@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ELK5Wgpz;       spf=pass
 (google.com: domain of susanwilson58jj@gmail.com designates
 2607:f8b0:4864:20::b44 as permitted sender) smtp.mailfrom=susanwilson58jj@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

--000000000000f861a3062f81c392
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

KuacgOi/keWlveWQl++8nyoNCg0K6JSs6I+c77yM5L2c5Li65oiR5Lus5pel5bi46aWu6aOf5Lit
5LiN5Y+v5oiW57y655qE5LiA6YOo5YiG77yM5Li65oiR5Lus5o+Q5L6b5LqG5Liw5a+M55qE57u0
55Sf57Sg44CB55+/54mp6LSo5ZKM6Iaz6aOf57qk57u077yM5a+557u05oyB6Lqr5L2T5YGl5bq3
6LW3552A6Iez5YWz6YeN6KaB55qE5L2c55So44CCDQoNCuS9huS9oOefpemBk++8n+acieS6m+iU
rOiPnOWmguaenOS4jee7j+i/h+eEr+awtOi/meS4gOeugOWNleeahOatpemqpO+8jOWwseWPr+iD
veaRh+i6q+S4gOWPmO+8jOaIkOS4uuWNseWus+WutuS6uuWBpeW6t+eahOKAnOmakOW9ouadgOaJ
i+KAneOAgg0KDQrku6XkuIvmmK/mlofnq6DnmoTkuLvopoHlhoXlrrnvvJoNCg0KaHR0cHM6Ly90
aW55dXJsLmNvbS9CdS1jaGFvLXNodWktY2hpLWppdTINCg0K5oSf6LCi5L2g6ZiF6K+76L+Z56+H
5paH56ug77yBDQoNCi0tLQ0KDQrnnJ/nm7jmnIDnu4jkvJrmmL7njrDvvIzlhazkuYnnu4jlsIbl
rp7njrDjgIINCg0KLS0gCllvdSByZWNlaXZlZCB0aGlzIG1lc3NhZ2UgYmVjYXVzZSB5b3UgYXJl
IHN1YnNjcmliZWQgdG8gdGhlIEdvb2dsZSBHcm91cHMgImthc2FuLWRldiIgZ3JvdXAuClRvIHVu
c3Vic2NyaWJlIGZyb20gdGhpcyBncm91cCBhbmQgc3RvcCByZWNlaXZpbmcgZW1haWxzIGZyb20g
aXQsIHNlbmQgYW4gZW1haWwgdG8ga2FzYW4tZGV2K3Vuc3Vic2NyaWJlQGdvb2dsZWdyb3Vwcy5j
b20uClRvIHZpZXcgdGhpcyBkaXNjdXNzaW9uIHZpc2l0IGh0dHBzOi8vZ3JvdXBzLmdvb2dsZS5j
b20vZC9tc2dpZC9rYXNhbi1kZXYvQ0FNYTNEMEZKRW1rSEU3dkwwRE01MyUyQnFQMndVZ2ZReFRn
Y3hONkpiJTNEZmMyRHA5NlR4dyU0MG1haWwuZ21haWwuY29tLgo=
--000000000000f861a3062f81c392
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: base64

PGRpdiBkaXI9Imx0ciI+PHAgY2xhc3M9ImdtYWlsLWF1dG8tc3R5bGUxIiBzdHlsZT0iZm9udC1m
YW1pbHk6JnF1b3Q7TWljcm9zb2Z0IFlhSGVpJnF1b3Q7O2NvbG9yOnJnYigwLDAsMCk7Zm9udC1z
aXplOm1lZGl1bSI+PHN0cm9uZz7mnIDov5Hlpb3lkJfvvJ88L3N0cm9uZz48L3A+PHAgY2xhc3M9
ImdtYWlsLWF1dG8tc3R5bGUxIiBzdHlsZT0iZm9udC1mYW1pbHk6JnF1b3Q7TWljcm9zb2Z0IFlh
SGVpJnF1b3Q7O2NvbG9yOnJnYigwLDAsMCk7Zm9udC1zaXplOm1lZGl1bSI+6JSs6I+c77yM5L2c
5Li65oiR5Lus5pel5bi46aWu6aOf5Lit5LiN5Y+v5oiW57y655qE5LiA6YOo5YiG77yM5Li65oiR
5Lus5o+Q5L6b5LqG5Liw5a+M55qE57u055Sf57Sg44CB55+/54mp6LSo5ZKM6Iaz6aOf57qk57u0
77yM5a+557u05oyB6Lqr5L2T5YGl5bq36LW3552A6Iez5YWz6YeN6KaB55qE5L2c55So44CCPC9w
PjxwIGNsYXNzPSJnbWFpbC1hdXRvLXN0eWxlMSIgc3R5bGU9ImZvbnQtZmFtaWx5OiZxdW90O01p
Y3Jvc29mdCBZYUhlaSZxdW90Oztjb2xvcjpyZ2IoMCwwLDApO2ZvbnQtc2l6ZTptZWRpdW0iPuS9
huS9oOefpemBk++8n+acieS6m+iUrOiPnOWmguaenOS4jee7j+i/h+eEr+awtOi/meS4gOeugOWN
leeahOatpemqpO+8jOWwseWPr+iDveaRh+i6q+S4gOWPmO+8jOaIkOS4uuWNseWus+WutuS6uuWB
peW6t+eahOKAnOmakOW9ouadgOaJi+KAneOAgjwvcD48cCBjbGFzcz0iZ21haWwtYXV0by1zdHls
ZTEiIHN0eWxlPSJmb250LWZhbWlseTomcXVvdDtNaWNyb3NvZnQgWWFIZWkmcXVvdDs7Y29sb3I6
cmdiKDAsMCwwKTtmb250LXNpemU6bWVkaXVtIj7ku6XkuIvmmK/mlofnq6DnmoTkuLvopoHlhoXl
rrnvvJo8L3A+PHAgY2xhc3M9ImdtYWlsLWF1dG8tc3R5bGUxIiBzdHlsZT0iZm9udC1mYW1pbHk6
JnF1b3Q7TWljcm9zb2Z0IFlhSGVpJnF1b3Q7O2NvbG9yOnJnYigwLDAsMCk7Zm9udC1zaXplOm1l
ZGl1bSI+PGEgaHJlZj0iaHR0cHM6Ly90aW55dXJsLmNvbS9CdS1jaGFvLXNodWktY2hpLWppdTIi
Pmh0dHBzOi8vdGlueXVybC5jb20vQnUtY2hhby1zaHVpLWNoaS1qaXUyPC9hPjwvcD48cCBjbGFz
cz0iZ21haWwtYXV0by1zdHlsZTEiIHN0eWxlPSJmb250LWZhbWlseTomcXVvdDtNaWNyb3NvZnQg
WWFIZWkmcXVvdDs7Y29sb3I6cmdiKDAsMCwwKTtmb250LXNpemU6bWVkaXVtIj7mhJ/osKLkvaDp
mIXor7vov5nnr4fmlofnq6DvvIE8L3A+PHAgY2xhc3M9ImdtYWlsLWF1dG8tc3R5bGU5IiBzdHls
ZT0iZm9udC1zaXplOjExLjVwdDtjb2xvcjpyZ2IoOTEsMTAyLDExNikiPi0tLTwvcD48cCBjbGFz
cz0iZ21haWwtYXV0by1zdHlsZTE0IiBzdHlsZT0iZm9udC1mYW1pbHk6JnF1b3Q7TWljcm9zb2Z0
IFlhSGVpJnF1b3Q7O2NvbG9yOnJnYigwLDEyMywyNTUpO2ZvbnQtc2l6ZTptZWRpdW0iPuecn+eb
uOacgOe7iOS8muaYvueOsO+8jOWFrOS5iee7iOWwhuWunueOsOOAgjwvcD48L2Rpdj4NCg0KPHA+
PC9wPgoKLS0gPGJyIC8+CllvdSByZWNlaXZlZCB0aGlzIG1lc3NhZ2UgYmVjYXVzZSB5b3UgYXJl
IHN1YnNjcmliZWQgdG8gdGhlIEdvb2dsZSBHcm91cHMgJnF1b3Q7a2FzYW4tZGV2JnF1b3Q7IGdy
b3VwLjxiciAvPgpUbyB1bnN1YnNjcmliZSBmcm9tIHRoaXMgZ3JvdXAgYW5kIHN0b3AgcmVjZWl2
aW5nIGVtYWlscyBmcm9tIGl0LCBzZW5kIGFuIGVtYWlsIHRvIDxhIGhyZWY9Im1haWx0bzprYXNh
bi1kZXYrdW5zdWJzY3JpYmVAZ29vZ2xlZ3JvdXBzLmNvbSI+a2FzYW4tZGV2K3Vuc3Vic2NyaWJl
QGdvb2dsZWdyb3Vwcy5jb208L2E+LjxiciAvPgpUbyB2aWV3IHRoaXMgZGlzY3Vzc2lvbiB2aXNp
dCA8YSBocmVmPSJodHRwczovL2dyb3Vwcy5nb29nbGUuY29tL2QvbXNnaWQva2FzYW4tZGV2L0NB
TWEzRDBGSkVta0hFN3ZMMERNNTMlMkJxUDJ3VWdmUXhUZ2N4TjZKYiUzRGZjMkRwOTZUeHclNDBt
YWlsLmdtYWlsLmNvbT91dG1fbWVkaXVtPWVtYWlsJnV0bV9zb3VyY2U9Zm9vdGVyIj5odHRwczov
L2dyb3Vwcy5nb29nbGUuY29tL2QvbXNnaWQva2FzYW4tZGV2L0NBTWEzRDBGSkVta0hFN3ZMMERN
NTMlMkJxUDJ3VWdmUXhUZ2N4TjZKYiUzRGZjMkRwOTZUeHclNDBtYWlsLmdtYWlsLmNvbTwvYT4u
PGJyIC8+Cg==
--000000000000f861a3062f81c392--

Return-Path: <kasan-dev+bncBDPM3GPHUIARBQFFY2VQMGQEYEE7K3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 6240E8084D4
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Dec 2023 10:39:14 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-35d60bf7a23sf738985ab.1
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Dec 2023 01:39:14 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701941953; x=1702546753; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MsY7y9ASUOWO1RaRxB6ae28fPCeziJf24/G4/U2IoGQ=;
        b=tFSxb/uw20PjdeWR9WRDLIp9KNxUVdCXPKEATodBqCMN5MvoRMkGNRj/j81GR4NUyr
         QmmwK4HSIB863Ts2HX+vIDipmISt4Ggvc3IAzeCoaPpWWtjVZPrl1yif9pg1GlpOqMe1
         jsM3X6G2O6q+vMXwGILKFF5XR8hqc3d1zNYMzac543LwqMa9j5YQPSa2lTYGexIyrdOE
         q6do42pFIrfVW31XPjGuj9ezBOR93Z948p8qL9M1TNdhMKdg3G25HHqtJE6ePYxOVY7E
         OB6BboUG0s7YeZtYtdnoSxWCkIGD+NUBMzqZ6ZSjzdZXZcDm+n1IAJRH3YbhvrmmcFJh
         xpNg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1701941953; x=1702546753; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MsY7y9ASUOWO1RaRxB6ae28fPCeziJf24/G4/U2IoGQ=;
        b=Ju3LRZSnJgrMqbzTL1tBxd4fhmdb/kbBBPj4x9ArwpyWsrCAeFJY5JcMLAuOAv3i1H
         c0UMD8wF4hRhrCcE3FH1UMuVWQO+7Vku6JLxdCjKQamWgo/Wt3iexqgSVzEMt3chUdU0
         NKvIJ4WscNATJ9PACE9klhH4iXgwI180czK6JDj+ryuS5uymj7cSC+DqtKWpE9pQXCCG
         +nfg90t//pR/OgL5/EoRE9csNNKRh/RbK08TmVQnUo9AmbMkzlw00XR/+smcSQMv1Mg4
         I1IVbzyTCzgRVOG9amNTRPdLO3z/eIsMq7CTUGF6hoOcUVnLCNJrl47LvUjEqeuQSlXp
         583g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701941953; x=1702546753;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:message-id:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MsY7y9ASUOWO1RaRxB6ae28fPCeziJf24/G4/U2IoGQ=;
        b=gEF3rQvduoYY8SecAKXhCPrB1zQtM2GGnYohJiAF/V+Y9Le5sn4zzH7kSgqiam3WJE
         INCn6IajvC3/HG9Jr/nM2UfuYvrUO5Q/IUi1fGuRseEYPgy33YMW0nwocIWqM+943mSy
         g9DXhC5yuq+IUOCN56mSVFkzNpn5/a83oa55P7bMfE3VUvqLTG5AA6dotdJEV/dOUcxK
         aLQWbjTuu5Fv5o0MhbjqTLqFjvDBmi8M+hoG4LjD72or3FHGiZLhX30UtYEYFPRpdlCB
         uyNZTT9JSnNRe7Koz0TcsQtRHxcUnqdRVxZ05utYp1KGXDO9wVGwOvRPltR/veGKMak2
         2CrQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwdTVpYOpTKO/k5IOBBu3uq3q8KW8fbKGhYPBL1+NcSogEMEIP1
	0N+8UORCmn2Xel7K+Ykgs2k=
X-Google-Smtp-Source: AGHT+IGfOjj6M+V5Ee7T1SanD3xWt12cd9t98aJTfoG0CwRzV2JL1+wggSLjLX/1R+aFB5L+FdW9XQ==
X-Received: by 2002:a05:6e02:1a8b:b0:35d:12d4:a2e2 with SMTP id k11-20020a056e021a8b00b0035d12d4a2e2mr476189ilv.9.1701941952809;
        Thu, 07 Dec 2023 01:39:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:605:b0:58d:6d88:2214 with SMTP id
 e5-20020a056820060500b0058d6d882214ls203491oow.2.-pod-prod-05-us; Thu, 07 Dec
 2023 01:39:12 -0800 (PST)
X-Received: by 2002:a05:6808:a08:b0:3b9:d7a1:c9c with SMTP id n8-20020a0568080a0800b003b9d7a10c9cmr1405539oij.5.1701941952037;
        Thu, 07 Dec 2023 01:39:12 -0800 (PST)
Date: Thu, 7 Dec 2023 01:39:11 -0800 (PST)
From: Jeannelisan G <jeannelisang@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <34da1b10-c096-4254-b50e-4adf7b39c3b7n@googlegroups.com>
Subject: Victoria 4.46b Full 224
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_4394_1093730839.1701941951447"
X-Original-Sender: jeannelisang@gmail.com
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

------=_Part_4394_1093730839.1701941951447
Content-Type: multipart/alternative; 
	boundary="----=_Part_4395_965045772.1701941951448"

------=_Part_4395_965045772.1701941951448
Content-Type: text/plain; charset="UTF-8"

Dysk: Samsung HD753LJ Firmware: 1AA01107SMART z Victoria 4.46b Freeware 
(12.08.2008)SAMSUNG HD753LJ S13UJ1NQ112748------------------------... ID 
Name Value Worst Tresh Raw 
Health--------------------------------...\n\nvictoria 4.46b full 
224\nDownload https://rajemessa.blogspot.com/?rk=2wIQV8\n\n\n eebf2c3492\n

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/34da1b10-c096-4254-b50e-4adf7b39c3b7n%40googlegroups.com.

------=_Part_4395_965045772.1701941951448
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div>Dysk: Samsung HD753LJ Firmware: 1AA01107SMART z Victoria 4.46b Freewar=
e (12.08.2008)SAMSUNG HD753LJ S13UJ1NQ112748------------------------... ID =
Name Value Worst Tresh Raw Health--------------------------------...\n\nvic=
toria 4.46b full 224\nDownload https://rajemessa.blogspot.com/?rk=3D2wIQV8\=
n\n\n eebf2c3492\n</div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/34da1b10-c096-4254-b50e-4adf7b39c3b7n%40googlegroups.c=
om?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgi=
d/kasan-dev/34da1b10-c096-4254-b50e-4adf7b39c3b7n%40googlegroups.com</a>.<b=
r />

------=_Part_4395_965045772.1701941951448--

------=_Part_4394_1093730839.1701941951447--

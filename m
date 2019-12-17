Return-Path: <kasan-dev+bncBC3JRV7SWYEBBFVS4TXQKGQEHKYG5IY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0FC1A123457
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Dec 2019 19:06:16 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id v3sf8164897qvm.2
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Dec 2019 10:06:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576605975; cv=pass;
        d=google.com; s=arc-20160816;
        b=OTbZZFUW/kZUn5gK8n+VX8Yxwzn1hyTOxmY045lEuxRD2QyCfaRudnP37CWfVkF0Rn
         xuGdrAd5Yblch2K5hfgcpFwHLyBKGPxckhrDQ4Xlyyl7DPOQNp/0Ckx9LSgHDB3aANY5
         I6iFIuZxVEv40Wt2Nn6xdOGzpyN2m+lbq+bjW/GWpRcwfqC6FImelx2UkK3amzczD8jm
         ETX1T8AZUtIoGzUQnMJjjdUFWrzfsIRQgHSVgVLP/Dexi3SUUQTGKmP98Zt5qOmm9hel
         pjrwl0YvXqF6TgPamROg6NMA3vzrY2tb173807FXagCbxKSNxeMzCkE1vuEJmat4WhSs
         9LxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id
         :content-transfer-encoding:cc:date:in-reply-to:from:subject
         :mime-version:sender:dkim-signature;
        bh=uQMFB2ORcdjIpXMQWC4Tnz7QQEjsrJNPW1Oj+6IDvUI=;
        b=tk259q03uGvpXcw8bbp0eZr9/b/tEpWbnYv2kggcdHsvy+V9Ch/idpfp/Ggl6P8roJ
         a1GVin2+wpzHnFpe2C1sPdcva2DOAxLotJfLcnf0UM0PtjqOiAClEUIAhypEq3JN2rfW
         avWLhoyNM6tXHTz661J5G2B1D/6cj5codIUoquYrkmqsdpayCg0AhBjvPv26PjgRMcLF
         Zc1C8Hfw+hkrIL3LFeT+F2y9dzARSwbcL2GFevRzGh5g/uTxTQdL7uYKstrsmXF7kqo5
         hwIDSVO+aLkoFsT5rSDQ5S4CwUAdYnsPlXt9Oe67t21lT+DAT11xsAGLuDEdJintmS4s
         vTWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2019-08-05 header.b=JMg4G6wM;
       spf=pass (google.com: domain of boris.ostrovsky@oracle.com designates 156.151.31.86 as permitted sender) smtp.mailfrom=BORIS.OSTROVSKY@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:subject:from:in-reply-to:date:cc
         :content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uQMFB2ORcdjIpXMQWC4Tnz7QQEjsrJNPW1Oj+6IDvUI=;
        b=VsmHjOzt+gV80ye1Yb167MRiqV6NYoQRigbd7RtNdkUrHdolvNeOailAg8mxJivFE+
         BjU6nKFpsFjMabMVtHI97X8Atxhs6WyWoQS9gtzwXv8ffWfNYn1iZe2F7VmMghdVVJES
         ybKK8iPDq338JPBsYipAOGKnJzu7lUNX04RypQCarZyQjv+gclo/Ia2VHBG378TFWsR3
         ElR93TxvP2gnN03z3lUrBdWQW5c+i7BFeH9A101nWBnKBTF8gzmoKmBsVTHOe6aOfvP4
         4HK7CS/Pe8fUg7yaELQqJ6vJ0It9uQmDYB/PlcQsKJJN4gv4CcmrhJ9lFVHGyKzODzdO
         D5Bg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:subject:from:in-reply-to
         :date:cc:content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=uQMFB2ORcdjIpXMQWC4Tnz7QQEjsrJNPW1Oj+6IDvUI=;
        b=KzzTOHzIAHZPChFXL7ozmSoLqDG0oxfC+zPBdqe+XFcVw+y5rof4eB57N3Dzg9abcZ
         5MadUQiacSh9J7Rc5iVtkSvlHwmQE3tILJ3jo6P9NQMCUCXpENv2Ln3rOT91WJ2WQWyY
         MJbZAZl9kK2EijkiQuoLILZ46aAKk5v0Sag6ggqlu/lTcBNioWX1c/QA2n51P55b3/a1
         LSOfrxJ/BfAR+loX1+hPhuDa52NHM5/hs6lPfaVNnLd+IScm3al0kj0J5y4/MC2Rzvka
         WNp3hf4uxe1t3ZFqLZMgb+1FoUjIj6npirhi5Ou5r8PGn2sbnig+y92AKUlhIXlMMp5y
         ZmgQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXxE5Klxy0LvyI/F0FU9c5LCE3FhzePUis7EyIHbIkdP/64XJQ+
	ax4vBDaudiz9aIc+tpb/Fcc=
X-Google-Smtp-Source: APXvYqzem0/iNbT93OVKjS9AYT0Ww0iieIHWzXiamQ8iQ3GGnjV1srp8mp1/XDYkt9vAMhf8PYr8AQ==
X-Received: by 2002:a05:620a:1666:: with SMTP id d6mr6495006qko.379.1576605975030;
        Tue, 17 Dec 2019 10:06:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:110c:: with SMTP id e12ls3481507qvs.3.gmail; Tue,
 17 Dec 2019 10:06:14 -0800 (PST)
X-Received: by 2002:a05:6214:146e:: with SMTP id c14mr6048896qvy.82.1576605974670;
        Tue, 17 Dec 2019 10:06:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576605974; cv=none;
        d=google.com; s=arc-20160816;
        b=pgpapsisakVJL6osERxiuriFvDN6c+WPjccMDf/9MOcL7iDRutQKtDYSkbT4z9Hi9E
         a1u1XiuZqQb/ffEcCa0sxhLY+hTelKYgHL2O/aXP37zsnNZDWQlWJ14U1ndkZxh11a2O
         0FgzZPIfImvZu3o+aVj4mMtb9GOAFEjnsy3VYqaoAVgG7VUQuI3BmgGw6Su/vfmsl3bG
         rO6Wb5muj2/dPL4MiLU4IXreqN8oITdXNPri4/1Uiwtrn2hv6tQdT6XSW4ZGWGv2Qz6Z
         AdeL8KHw8y8OAmxtli5GaMrstDQtm/qFbqCVRoRBgaFChB7q5ML85k/IVK/uU86j7gKR
         0a7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=T+GnWQ1AKZOIs5s0xU8NEiourpCMeoVx+dHg7sen55I=;
        b=DaR7FoHciLTCw1iwEB6ReUHEcB1JF7MFHmbJ3lH2exwvqD+73oHcM5WeYG0TbIXGGD
         yuY81xoKx0oU62W0BdciMUBBuoH1BidKAHjVHiG++XD5T+qLL8dsqSAcKgw10hKKkddv
         /5X5yytgqsIooP+i6tC5sV2gX2J/I+Ha6cfbw1ATu4O0A7JJ4J8LIr3P8Jc9Fbzg8vxK
         DGqfyXaDQxGAeYqeIOqqVbOd7UhfgOvGI+LcTYxpK1Rh74R0PBm3CWQs7cpUyRawHsox
         xp0GmcVLSVLoPt2L2MCHVZXzN+W0pBYM4ttD4VzVEFCSPMjSLpyB4dRL4hzeaPKtNWqW
         mPKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@oracle.com header.s=corp-2019-08-05 header.b=JMg4G6wM;
       spf=pass (google.com: domain of boris.ostrovsky@oracle.com designates 156.151.31.86 as permitted sender) smtp.mailfrom=BORIS.OSTROVSKY@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
Received: from userp2130.oracle.com (userp2130.oracle.com. [156.151.31.86])
        by gmr-mx.google.com with ESMTPS id l9si1034877qkg.5.2019.12.17.10.06.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 17 Dec 2019 10:06:14 -0800 (PST)
Received-SPF: pass (google.com: domain of boris.ostrovsky@oracle.com designates 156.151.31.86 as permitted sender) client-ip=156.151.31.86;
Received: from pps.filterd (userp2130.oracle.com [127.0.0.1])
	by userp2130.oracle.com (8.16.0.27/8.16.0.27) with SMTP id xBHI524Y084487;
	Tue, 17 Dec 2019 18:06:11 GMT
Received: from userp3020.oracle.com (userp3020.oracle.com [156.151.31.79])
	by userp2130.oracle.com with ESMTP id 2wvq5ugh4h-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 17 Dec 2019 18:06:11 +0000
Received: from pps.filterd (userp3020.oracle.com [127.0.0.1])
	by userp3020.oracle.com (8.16.0.27/8.16.0.27) with SMTP id xBHI3PGR012618;
	Tue, 17 Dec 2019 18:06:11 GMT
Received: from aserv0122.oracle.com (aserv0122.oracle.com [141.146.126.236])
	by userp3020.oracle.com with ESMTP id 2wxm5nmcm3-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=OK);
	Tue, 17 Dec 2019 18:06:10 +0000
Received: from abhmp0014.oracle.com (abhmp0014.oracle.com [141.146.116.20])
	by aserv0122.oracle.com (8.14.4/8.14.4) with ESMTP id xBHI68Gi017125;
	Tue, 17 Dec 2019 18:06:08 GMT
Received: from [10.39.197.155] (/10.39.197.155)
	by default (Oracle Beehive Gateway v4.0)
	with ESMTP ; Tue, 17 Dec 2019 10:06:08 -0800
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0 (Mac OS X Mail 12.4 \(3445.104.11\))
Subject: Re: [RFC PATCH 0/3] basic KASAN support for Xen PV domains
From: Boris Ostrovsky <BORIS.OSTROVSKY@ORACLE.COM>
In-Reply-To: <20191217140804.27364-1-sergey.dyasli@citrix.com>
Date: Tue, 17 Dec 2019 13:06:05 -0500
Cc: xen-devel@lists.xen.org, kasan-dev@googlegroups.com,
        linux-kernel@vger.kernel.org,
        Andrey Ryabinin <aryabinin@virtuozzo.com>,
        Alexander Potapenko <glider@google.com>,
        Dmitry Vyukov <dvyukov@google.com>, Juergen Gross <jgross@suse.com>,
        Stefano Stabellini <sstabellini@kernel.org>,
        George Dunlap <george.dunlap@citrix.com>,
        Ross Lagerwall <ross.lagerwall@citrix.com>
Content-Transfer-Encoding: quoted-printable
Message-Id: <7301D02C-D33F-4205-BB32-C3E61015D26E@ORACLE.COM>
References: <20191217140804.27364-1-sergey.dyasli@citrix.com>
To: Sergey Dyasli <sergey.dyasli@citrix.com>
X-Mailer: Apple Mail (2.3445.104.11)
X-Proofpoint-Virus-Version: vendor=nai engine=6000 definitions=9474 signatures=668685
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 suspectscore=0 malwarescore=0
 phishscore=0 bulkscore=0 spamscore=0 mlxscore=0 mlxlogscore=999
 adultscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.0.1-1911140001 definitions=main-1912170142
X-Proofpoint-Virus-Version: vendor=nai engine=6000 definitions=9474 signatures=668685
X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 priorityscore=1501 malwarescore=0
 suspectscore=0 phishscore=0 bulkscore=0 spamscore=0 clxscore=1011
 lowpriorityscore=0 mlxscore=0 impostorscore=0 mlxlogscore=999 adultscore=0
 classifier=spam adjust=0 reason=mlx scancount=1 engine=8.0.1-1911140001
 definitions=main-1912170142
X-Original-Sender: boris.ostrovsky@oracle.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@oracle.com header.s=corp-2019-08-05 header.b=JMg4G6wM;
       spf=pass (google.com: domain of boris.ostrovsky@oracle.com designates
 156.151.31.86 as permitted sender) smtp.mailfrom=BORIS.OSTROVSKY@oracle.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=oracle.com
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



> On Dec 17, 2019, at 9:08 AM, Sergey Dyasli <sergey.dyasli@citrix.com> wro=
te:
>=20
> This series allows to boot and run Xen PV kernels (Dom0 and DomU) with
> CONFIG_KASAN=3Dy. It has been used internally for some time now with good
> results for finding memory corruption issues in Dom0 kernel.
>=20
> Only Outline instrumentation is supported at the moment.
>=20
> Patch 1 is of RFC quality
> Patches 2-3 are independent and quite self-contained.


Don=E2=80=99t you need to initialize kasan before, for example, calling kas=
an_alloc_pages() in patch 2?

-boris

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/7301D02C-D33F-4205-BB32-C3E61015D26E%40ORACLE.COM.

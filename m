Return-Path: <kasan-dev+bncBC24VNFHTMIBB5PPU76AKGQEXRE2ZQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C61C290C62
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Oct 2020 21:43:50 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id t15sf2276521pja.7
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Oct 2020 12:43:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602877429; cv=pass;
        d=google.com; s=arc-20160816;
        b=U+TrEsdJAoYrwu1xDbMqCU9w6UMC1HFcp4IKWXtRL783AhFkXpE9I3tccEigYLRSS1
         5OBmasDY8aN+Qqac8dCX+vR3oS10fu29tTAKZTpG2nfCTjmftaE85lODTe7308qaIIkK
         vg70GWo8TAKPPTWvKyTdvojdbY2PZUWeWSP1Cnm6NcDh1WdrPaon0CWgprshGcbZkaSu
         qZhnaKdl/AQAM8vI8LKB93fh9yyr3MV5adnLv1qqR/YSs4/Y/5U30NtKG7Cdqp8/zWqa
         C+7yy7izqEv9cSz1pWfA6UNhX48GaxRyicUhz/whSLs9L3Qz3hapDy4QgcE1UGCi3kWC
         6Pmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=s3B7Bo27W7ayzZGL2o4+nzANjluqO+QSwqur4UitwnU=;
        b=hERzQa03Y+RXZ8ePELp4NTlC4hjz91j/iekg3eybA99FpMOWZ1QILPiZJjaIA9AvUU
         /IXP5aytSHs8G6M2pt/V5MPQxdwtpKGWxtb7YwVK/EzSJii5ouRH5YrqqU2DtBfNkLwp
         SvK0GS49qs8GEduouWnyvW3FGfkbNjjCQtvaQyj5/FycnUaV9ihdAyTJHKebOBvrlXeW
         DEBjJFCfBOVn9GSqr5qDXRypou5XnvDtB0zLNZUzkbstmCpCnZGq4HRRFE78puGE+0Qx
         +270bsuuyV5/sKQfQOrd96qXA60HMIF2Aj+O5OqlMqo65nkHakFqEgPiZR90DgzJm6xQ
         eUOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=zkmu=dx=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=zKmU=DX=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=s3B7Bo27W7ayzZGL2o4+nzANjluqO+QSwqur4UitwnU=;
        b=UcxlHtds5bjM7uo1TtqTsgbQ73CVGaxZZV0e8fvVYCSx5kx9HMp8nbvO15EkeuTYSt
         Duyw9uRrac0Oi629sZRB7TqZVu7pxAuX25vh/HwgeLXwtkTIGTArJaum8RmbZmxfG7pd
         godkJAYptLNEUWRXs0XV6dquF5x/OyYUeNV8YGXqhW8dIxMxIGhyuGteQCiPHmC1v/bZ
         WTY3nftqB5eE5dvb1us/eZhCjnZmNQDJYDD2VvTyuzsveF72iUOD28qji6Fz4HV5bIZz
         m/Vj/8/9fw2s6TNuhKJPKnpDB3ZPntar439SLz19R4AhsY78Xg6CriYJfWhNQl5nBsL3
         Lckg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=s3B7Bo27W7ayzZGL2o4+nzANjluqO+QSwqur4UitwnU=;
        b=uSz82hlwVf7TLKcX7K0bY53qBUHTdN3lBT7eBYTqFbYixanwp711H5N/0y3QZUk7Nc
         ozmtECr1eJK8he/SX/Pdx19wiTvIMiMrRxmX0Vih5A0sLOqsu3TVMIiZLbIiluvWILuC
         jq+DeSSHraevJrYIrHsKhP2ZDHChFkTUlMSd/KTkjgYwdWcNIiZSjD4WgPzI9n1mULqM
         QF9Hogee9eF6Y9MeiPt8G38sKCGG5GIgA3L0F/7ZEZymsCarMscweh/xRV7a5MtqeMjZ
         FhAESrIIbrljlRq71kJgkBVXUepLofpmE8BDawyttUmhhzE4ldwGweOTydnJUNodXCcG
         EIVA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5312N7a/8pEwNZXDRczK1EhnkqAJm33ljF4N+txYAuyx13rVA/TE
	ZKEvoNjDB4nJPttleMXAAFk=
X-Google-Smtp-Source: ABdhPJzy0+6DAPfxPssy//WIg8lu52FA2lJvtNEdibII0AnsEpUpl45qelAMq85/szB6UgWrYZuA+g==
X-Received: by 2002:a17:902:8543:b029:d3:9c44:7230 with SMTP id d3-20020a1709028543b02900d39c447230mr5502314plo.10.1602877429207;
        Fri, 16 Oct 2020 12:43:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b596:: with SMTP id a22ls1737890pls.7.gmail; Fri, 16
 Oct 2020 12:43:48 -0700 (PDT)
X-Received: by 2002:a17:902:eeca:b029:d3:d8dd:3e4b with SMTP id h10-20020a170902eecab02900d3d8dd3e4bmr5830496plb.68.1602877428611;
        Fri, 16 Oct 2020 12:43:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602877428; cv=none;
        d=google.com; s=arc-20160816;
        b=LknbF0Vil4jlgEOnW0160vGSmRSCpIzAUHQNYyqw5bC9+dKEqXLlfB9h7y16Z/pXAZ
         cNuSBsTCWwmehnILE/muqKwyRtxsv3F+xk0I2DF7NJzIg8QX9ordnyQq9UhHIdjPVzD/
         ud0Gsrjsml/xjRJ/Y3OtNVvu6TLEAYe47pOO8hGYnGt/lakVw3Trj0ytLIeNxrIGpmE6
         l6b6xlnXkdScVQV6rIurQIbw45Cc5I1DkZs5uOmAwUd7wVD4/xV8hyok7GmnCA4axVJl
         jv4Fhu1X/7Ml5c/4BAjfOIbk7TsuNTNpxstbGcexxks9NRu+y1YOnY1F6+FjJT6PusZy
         xe+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=a9JidWKsI2zWwrAGG65e9AiluTOXnDaKieGckiGIS18=;
        b=cT/F78AmWpZ0Xb9Q57HXnRefsv+mMOATeRnrEpM/4eXd+5OTBboaXm/CTi+ECWLce9
         Vj1nZmTu2oVYWk5s9YJfRm4c83KvOr2Zri+uBdGm9eeNTNPC1T/rModlzQHfxzzhIctG
         h0WWizBnkl05+SfB5hkJgBL12ni04zQ8c43tS76RukN3lkKMmSl4bWzPgN+hdOM2SG41
         VTIpnIqXgcBRka1gWdhtGONP3zNVGhk+/yBf6XerqixiWqyFDN2ncwI5aC64jBiefdgb
         dSW5YtBbqpTnnrWElcjqYPEWzVAH4ZfExBje//9tqGBQHcw9K+DuhJbWZryAf6Fu2s0d
         l69Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of srs0=zkmu=dx=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=zKmU=DX=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id q2si249655pfc.0.2020.10.16.12.43.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 16 Oct 2020 12:43:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=zkmu=dx=bugzilla.kernel.org=bugzilla-daemon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203493] KASAN (sw-tags): add global variables support
Date: Fri, 16 Oct 2020 19:43:47 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: short_desc
Message-ID: <bug-203493-199747-aOjE2GaINw@https.bugzilla.kernel.org/>
In-Reply-To: <bug-203493-199747@https.bugzilla.kernel.org/>
References: <bug-203493-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of srs0=zkmu=dx=bugzilla.kernel.org=bugzilla-daemon@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=zKmU=DX=bugzilla.kernel.org=bugzilla-daemon@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=203493

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
            Summary|KASAN: add global variables |KASAN (sw-tags): add global
                   |support for clang           |variables support

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-203493-199747-aOjE2GaINw%40https.bugzilla.kernel.org/.

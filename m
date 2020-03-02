Return-Path: <kasan-dev+bncBC27HSOJ44LBB4EL6XZAKGQE2NWRTGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id ADF6017615F
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Mar 2020 18:44:16 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id f10sf39609wrv.1
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2020 09:44:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583171056; cv=pass;
        d=google.com; s=arc-20160816;
        b=Rgs0Jy7cU6W5CREWOu0NjKxFyGK++VImRne0ZbfOfuTmgxLYL/oAkVfoQGu3dAtZKb
         LLtKK7af6wBgMWzcBC2ABHc1Jb0SfU7xiwDgPz28I/8FT/C87wUIZQVz4wopr0bLLP2W
         yRaHPZzxUxDkFS7QDj4xoYS1q6q7+Fk0TX658Zt7nxU7tcYJfo3XlV+WfetBwI7jJoLG
         57D6AhcNuS3bLMj6j1RzhxMgN+8wT92w1dO19KI/hFo//le5QnY3VfX/s3pfThqAZCEt
         BEN2NG2rcilOmYjUEK9Sf8DdxYkQOA/jCH/LjzJiaFmhouJI4CMF3l6gGxwyp5uWY3Rq
         sQrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from:sender:dkim-signature;
        bh=rj3EgfITzeaJ74V1PxHhIGeG18pku0ITmstO4ck3R3M=;
        b=PD6r0t7yK5518SvCLvjyE7sYNG9IaHhDciX2q4UR2WWdBZmWqhKnMy8HNw+zLYl7ve
         Bh9LFlTdcaSEE2KQ0kYLDXJHpPZVi0PW/tPEiU+Rp9dzeb6dh16Jz9Y4O+K8PM42oQT6
         zhvoZ6BA0OmWdd3f39QUsZT49F0qT5NyRR7rvLT0RPW43B4U1sPZicppnWP8NbvYUHQw
         ssyyQ6iIS2qMJmwF98/FBNSfsQxw5uaIfxSgZYHRJ4aqFyIVvfr2bTYnccedvm4Z/ouw
         ap8cQTzuOPpG7XGO5+YiUcJL2jhKgyvOfFd9vxSJOOqxNepmZPQoxvl1cDyeKaonxIMl
         TbbQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 207.82.80.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:thread-topic:thread-index:date:message-id
         :references:in-reply-to:accept-language:content-language
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rj3EgfITzeaJ74V1PxHhIGeG18pku0ITmstO4ck3R3M=;
        b=BRoK3c7uo1g3l8fNalJYNxo8MZNBGX8WeB+AEiYVGA6VOEOBW4KyvCrvkxiCYIaG0H
         5XVK4+hVb9xAwkEdM7ZjvKSo/Gn+6C3yZ5sTrn7xwaAJSKQ6P8WAneGwPZCIpohDShCh
         i3UNdC/8GJ5HTJNUvPZ+zWDhVb8tIy7l3/U8k5jTUIsUG/y4NoejgosMFgoByhonq5JU
         YJiigw30vAP9sBM1sPdyc2AoLRskxEY8AfRIwlr6o2D12ebBieTVduf6F8bKICppcjXz
         VYUt7iaC0tt7mMga9oNtJnK7Rix097FI3hI9eATDbmaZTbU6nL9mXvUKjVK7M6ufVIeC
         U27g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :content-language:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rj3EgfITzeaJ74V1PxHhIGeG18pku0ITmstO4ck3R3M=;
        b=IjD5bd6nuGNDiKEk3gttOmtHlWeCIGAQe3LHSjyIqyDy8MzpqAftChBdDxBb+1jKDc
         NDIEChTTt5cfljE6Xc1I+gQbZsuY09LQKxaXchgOuH3AfSeAo9Got+VRICwRP2C9yVMo
         2ApxPl1RQGPJSqDI4RnWXUyDSnL69Xa0VaUHPaZOxISpp+xk7kS4IkRdWHBOvYiiG+gq
         UTgwdMtNvt7o3dQihA+e7L3B9Y4xPr4UemdqzwShH5H++c93zjQmjkb81mvv8vqZoV+f
         CPcV8IaH9WQzT82CgBuQGI/w/iyl4F6tI+D7OpzPg5JnEQBcITUFPjoc4No+BXDL3kT8
         qBSw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ2BtY6UPA6D+dlBmlIuPohxw5LKV91joRqYtDGvHf1jNrq53EBo
	ucmAZpymoulWc1LOb579OJM=
X-Google-Smtp-Source: ADFU+vtoMQTJwQzp2q2C/vz2GAE7Szo7lPxw4Vl7EDMKNTiW6k5KbevS1aqIiyZnteF/AiCyBttycQ==
X-Received: by 2002:a05:600c:146:: with SMTP id w6mr68807wmm.180.1583171056377;
        Mon, 02 Mar 2020 09:44:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:2c03:: with SMTP id q3ls37161wmg.0.gmail; Mon, 02
 Mar 2020 09:44:15 -0800 (PST)
X-Received: by 2002:a1c:7f87:: with SMTP id a129mr204129wmd.160.1583171055841;
        Mon, 02 Mar 2020 09:44:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583171055; cv=none;
        d=google.com; s=arc-20160816;
        b=xj4O3DxAwC/ckKKk4uu2uN5n+wEnNNm7CC3RkyyfxH7i6pvc2Zil1n1mhZf74prar6
         10NFa6z3XHX75+j1We/14WOPo1eBwxfTXPkIqOnAQcYKRnZ6umO2aVjdXZWc6WGEQSaD
         85PkgS4OlXaVsKOHLTnxLZXtMU6na7hU2U9k7tTs6p/ijNwFUeNQLviqV6HGL975iGf1
         epfP2ub666uYX+5kA4aX7lbtQwFGgoSOHiikSKd+2OAQj/C7EVn86VaCJQnzsTBABdow
         zc8k3fetODAcoNvWXjt0qh6EHX/9OmkCfgnmSJ/SLjPlUEDX2w6byW+CzZmrjz9w5e+c
         hUHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from;
        bh=faJni8D6yzzVVdxsNrTWEBOMlcFtIoaCKGI+WYr+3iM=;
        b=GwwvOWssqTYavH9h8e2YcG5vr2M5LEdOdOP3XwJSA8J3s7i1zF2hQaXbFYjuL4RamL
         0gBiNjwCAZDhWjc38Md6TdkrgAg+Qgt0GueXUN+PBBdAzHGEWk6g0GgOGvtpCFaAND4L
         qD8id1PuVBPKMjIBPv+lBhdxe7iwihZE9ii4MQSjc7FcS2/0CXl7VNEY7Qtr/yUi71kh
         RIvgwCp5r9LWUIjOiRl34ifyjYqo614DNXveCziwvA32tNeFAFL9hwe/dj3MfnoocdIj
         //LSxwlM7vbRPqqmwW1J3yv+1b2enhhqwU0f0Dcs7LyxAJgHoXDgopPpX2cWV4JV2Mnh
         HCVw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of david.laight@aculab.com designates 207.82.80.151 as permitted sender) smtp.mailfrom=david.laight@aculab.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=aculab.com
Received: from eu-smtp-delivery-151.mimecast.com (eu-smtp-delivery-151.mimecast.com. [207.82.80.151])
        by gmr-mx.google.com with ESMTPS id l13si755385wrp.2.2020.03.02.09.44.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 02 Mar 2020 09:44:14 -0800 (PST)
Received-SPF: pass (google.com: domain of david.laight@aculab.com designates 207.82.80.151 as permitted sender) client-ip=207.82.80.151;
Received: from AcuMS.aculab.com (156.67.243.126 [156.67.243.126]) (Using
 TLS) by relay.mimecast.com with ESMTP id
 uk-mta-160-SXZ8HwqhNeywIeCkwMp4SA-1; Mon, 02 Mar 2020 17:44:12 +0000
X-MC-Unique: SXZ8HwqhNeywIeCkwMp4SA-1
Received: from AcuMS.Aculab.com (fd9f:af1c:a25b:0:43c:695e:880f:8750) by
 AcuMS.aculab.com (fd9f:af1c:a25b:0:43c:695e:880f:8750) with Microsoft SMTP
 Server (TLS) id 15.0.1347.2; Mon, 2 Mar 2020 17:44:11 +0000
Received: from AcuMS.Aculab.com ([fe80::43c:695e:880f:8750]) by
 AcuMS.aculab.com ([fe80::43c:695e:880f:8750%12]) with mapi id 15.00.1347.000;
 Mon, 2 Mar 2020 17:44:11 +0000
From: David Laight <David.Laight@ACULAB.COM>
To: 'Marco Elver' <elver@google.com>
CC: "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"stern@rowland.harvard.edu" <stern@rowland.harvard.edu>,
	"parri.andrea@gmail.com" <parri.andrea@gmail.com>, "will@kernel.org"
	<will@kernel.org>, "peterz@infradead.org" <peterz@infradead.org>,
	"boqun.feng@gmail.com" <boqun.feng@gmail.com>, "npiggin@gmail.com"
	<npiggin@gmail.com>, "dhowells@redhat.com" <dhowells@redhat.com>,
	"j.alglave@ucl.ac.uk" <j.alglave@ucl.ac.uk>, "luc.maranget@inria.fr"
	<luc.maranget@inria.fr>, "paulmck@kernel.org" <paulmck@kernel.org>,
	"akiyks@gmail.com" <akiyks@gmail.com>, "dlustig@nvidia.com"
	<dlustig@nvidia.com>, "joel@joelfernandes.org" <joel@joelfernandes.org>,
	"linux-arch@vger.kernel.org" <linux-arch@vger.kernel.org>
Subject: RE: [PATCH v2] tools/memory-model/Documentation: Fix "conflict"
 definition
Thread-Topic: [PATCH v2] tools/memory-model/Documentation: Fix "conflict"
 definition
Thread-Index: AQHV8J155VDezGAX9EWDGQvLVJz3h6g1j37g
Date: Mon, 2 Mar 2020 17:44:11 +0000
Message-ID: <8d5fdc95ed3847508bf0d523f41a5862@AcuMS.aculab.com>
References: <20200302141819.40270-1-elver@google.com>
In-Reply-To: <20200302141819.40270-1-elver@google.com>
Accept-Language: en-GB, en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-ms-exchange-transport-fromentityheader: Hosted
x-originating-ip: [10.202.205.107]
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: aculab.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: david.laight@aculab.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of david.laight@aculab.com designates 207.82.80.151 as
 permitted sender) smtp.mailfrom=david.laight@aculab.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=aculab.com
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

From: Marco Elver
> Sent: 02 March 2020 14:18
> 
> The definition of "conflict" should not include the type of access nor
> whether the accesses are concurrent or not, which this patch addresses.
> The definition of "data race" remains unchanged.
> 
> The definition of "conflict" as we know it and is cited by various
> papers on memory consistency models appeared in [1]: "Two accesses to
> the same variable conflict if at least one is a write; two operations
> conflict if they execute conflicting accesses."

I'm pretty sure that Linux requires that the underlying memory
subsystem remove any possible 'conflicts' by serialising the
requests (in an arbitrary order).

So 'conflicts' are never relevant.

There are memory subsystems where conflicts MUST be avoided.
For instance the fpga I use have some dual-ported memory.
Concurrent accesses on the two ports for the same address
must (usually) be avoided if one is a write.
Two writes will generate corrupt memory.
A concurrent write+read will generate a garbage read.
In the special case where the two ports use the same clock
it is possible to force the read to be 'old data' but that
constrains the timings.

On such systems the code must avoid conflicting cycles.

	David

-
Registered Address Lakeside, Bramley Road, Mount Farm, Milton Keynes, MK1 1PT, UK
Registration No: 1397386 (Wales)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8d5fdc95ed3847508bf0d523f41a5862%40AcuMS.aculab.com.

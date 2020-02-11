Return-Path: <kasan-dev+bncBDK3TPOVRULBBH6RRPZAKGQEIKNZPHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 29538159675
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2020 18:47:12 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id j1sf4088390lja.3
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2020 09:47:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581443231; cv=pass;
        d=google.com; s=arc-20160816;
        b=PdZSmiRmtnVTeDytCq+UcYCTPgnvgASTibN9nCFd30eYMnPXd0xkvK+ilit2xDYy/t
         h83VFQ+iESW9L6d3eOEZ4E2ugZVM41rTqXO8bArRCpXIf7pJ+MR8EOL83TuY8X+BYxRD
         w9zOuhGUGQeLD8FOUOtmCrHO8a+xTpkRgnqS7Qk/o97igJIsqXtQfsQULeCocfR8wsMB
         EJAKB8yRQSra3sFl17nJ3zSFu+G0XVStQdHPCTkMFkpIGhfUn9pUQaZ+IbpE4F1HerV+
         5FNJlUkLfsrZASLwPBJRe31q9ViWUcTbAsV4U0B+ZKNp81H5RvmSJvr00/3KpeDRjyPo
         tO9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=JiTt4/bHs/MIZIc/c1Pk/ApjHLsgNswjJKiBW9y7++0=;
        b=PSIXgRkNu0mYyqhZtNx2/TK5+8vWNB7WT+QtYzVgoPe/GEDk5fcg4VQufWTfNAnZoi
         lFPG0gh9CUCk5mdPXqboipg3zWTIvLJtncrCH/pvj1TAjnBPW2cSRweLtm0wCTsPPWRx
         Q8DTVtrAB83H4u/zp9FVfF7RTyP0V4xp8ZC2s2eJvdEr/0FLsPnx8sZY0dO3y+D/hgGk
         V31ZXsfpwqM3N6BmemBqx9tV6y6uV9Y0iDTi9TaTFKwJkVH4G4l6TSGIXEGncri1w2Kd
         5VFpPsSvy5/+6Kzv6nagXNJ/b417pFSzMzX0jglNQFEa1NTVfT8jbd0qkpFU6xhTAQue
         0VXQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QbpBWdwY;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JiTt4/bHs/MIZIc/c1Pk/ApjHLsgNswjJKiBW9y7++0=;
        b=cbLU6EIhAkc7754Km1kwjYMhK1rFZZAj/oAfKqrlgKBaecgbK+nxYIpv6kkkBFfkZ7
         7PPObHZ+w/Q5xmhZYy6EcmP0I/+iE0Bt8EXrslSbleoTyC0eoAGuZdHcNbCDm/nprPS+
         AZBEOoAgUJLUWBfSs/Pem9k4uZyeaD415N9Kuuce/VCE0uvMltGzQbjBplbWBLjf/da8
         d+Gm2mDkYmPSCkmVEmHxCszHekFp2h09Qn692wZjOz7WDh/IXFA1O+6zXOesGPEs0c1I
         f/2wQd7RsBCgMCFsMLsKa+YlW09OsP3LcXUUhIrv9O+JHivUuXoXhpz865o9FrKI/g7b
         1iTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JiTt4/bHs/MIZIc/c1Pk/ApjHLsgNswjJKiBW9y7++0=;
        b=EpUBxre5kZYavUd3/+u2mnQSzAHwW9W8eBDqaGWktZXOWBzxUhb/NrjvRDZImbjgSw
         bt3/w5WW2j24VKvzYPUiRpSed0CSJWO6V170OhHAwgTCEnk5/KSTEaCZawxvmL9Tcr7q
         AER1mMWwftB7fUUovp8d9qvhnWzrnOTFad9FuiTQBm/oAeilKgbbIdvT9ZnH6IC+Q6KJ
         GlH/n12UCkon8FUPuYjdefao4qZcbSRUoqisAmgGdf86ROYOTAN7Y7pRsNt1/5TnCEf+
         qkc9CnRX0A+TNV6SGkvw8s9VsUdQ/6rHZMqqNL0PGWgf8xkKeZY2k7RRV/W4H9E5KT8v
         CESw==
X-Gm-Message-State: APjAAAXxLL0EzJ2SLCNLyNe3mmbX0EVY2VBSbckavcnNSIBRpjbySWXC
	DnZ3Ihii/l2atMC9lgm6KaE=
X-Google-Smtp-Source: APXvYqzZMX2UMU8RsJZu6tMm+mSJ5ixL2bQi+B3rSxmBI0dcTYIx8vBXfQrxqwaJXl9qyWxnyZpguA==
X-Received: by 2002:a05:651c:cf:: with SMTP id 15mr5114347ljr.288.1581443231714;
        Tue, 11 Feb 2020 09:47:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9516:: with SMTP id f22ls2597549ljh.2.gmail; Tue, 11 Feb
 2020 09:47:11 -0800 (PST)
X-Received: by 2002:a2e:9041:: with SMTP id n1mr5000024ljg.133.1581443231140;
        Tue, 11 Feb 2020 09:47:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581443231; cv=none;
        d=google.com; s=arc-20160816;
        b=Ph2kOaBV2XJktsr7Jxy4780kloKtRZLsHyYNgd7izrrhJXdQGBjh6Mhh7A/fNKP7/8
         N00sDqTX0UKBlK4fy8CJGXeDZWf2ABia+7vZbvLRDS32ICKZtmi7N/kL6QfXcKr2mUgK
         Rd+/O89bVdYfzlCm7uI2RgVCM2FMzYlxnObCYHiZahWz2feDbIcqkizw2/vTyWqXgP4O
         ON41W0LPsKE4cpF5eMAMyaCvbWPePcYYXZ+0Ksk6354GWFEdchbyDbOusACMBg3XlbZE
         lOcHag6vRGVEPPfHbRAmnl06CO6AzPvh/PtFpW/1lNqpmqO57R7UqQcVd3gYJJ2MBkOS
         1p3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Z0VAV2uAZn7cwf80RoSqvTXJTOGM5LDaGHKNSoNSGHk=;
        b=w2u9II2INy0tEgBXjTNL2ZH+N1tg/k1VmmvxsiqSG1xJG3lfColfnTiBUy4CJAtD1V
         03Vr7Zn1gQ9sAyvuaRsQhgHm4d26wPcmAdJr1V+sgjhLqfGwnyS9R5wr4tDMlWT5A9Ce
         D4NPWGMaTG4UEJ0S/no+rQ4bOkhSRQwWwDI0YOqgpk46w3Th1Zr5e9h1XxBW/fSDLuuK
         dUTHD5/ue6m7SlBKoXs3EPHsdM5skVxshK3mQztFQ7RHsm8P+mTkFBaWjI8sFFS9Hkir
         OPTEGrvb5ydIQO3ARNR1uhYS6FYz4bUY0N0UucG2lCovQx8KYS5cBMZwHTtSYA3nhNko
         Nl9A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QbpBWdwY;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x442.google.com (mail-wr1-x442.google.com. [2a00:1450:4864:20::442])
        by gmr-mx.google.com with ESMTPS id d8si220651lji.0.2020.02.11.09.47.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Feb 2020 09:47:11 -0800 (PST)
Received-SPF: pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::442 as permitted sender) client-ip=2a00:1450:4864:20::442;
Received: by mail-wr1-x442.google.com with SMTP id w12so13540953wrt.2
        for <kasan-dev@googlegroups.com>; Tue, 11 Feb 2020 09:47:11 -0800 (PST)
X-Received: by 2002:a05:6000:108e:: with SMTP id y14mr9883732wrw.338.1581443230266;
 Tue, 11 Feb 2020 09:47:10 -0800 (PST)
MIME-Version: 1.0
References: <20200210225806.249297-1-trishalfonso@google.com> <CACT4Y+Y=Qj6coWpY107Dj+TsUJK1nruWAC=QMZBDC5snNZRTOw@mail.gmail.com>
In-Reply-To: <CACT4Y+Y=Qj6coWpY107Dj+TsUJK1nruWAC=QMZBDC5snNZRTOw@mail.gmail.com>
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 11 Feb 2020 09:46:59 -0800
Message-ID: <CAKFsvUL=maBVZ7v_N6W1skZRkYm4GacRGn-ohbf-o84p598XNQ@mail.gmail.com>
Subject: Re: [RFC PATCH v2] UML: add support for KASAN under x86_64
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, David Gow <davidgow@google.com>, 
	Brendan Higgins <brendanhiggins@google.com>, Johannes Berg <johannes@sipsolutions.net>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	linux-um@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=QbpBWdwY;       spf=pass
 (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::442
 as permitted sender) smtp.mailfrom=trishalfonso@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Patricia Alfonso <trishalfonso@google.com>
Reply-To: Patricia Alfonso <trishalfonso@google.com>
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

> I started reviewing this, but I am spotting things that I already
> commented on, like shadow start and about shadow size const. Please
> either address them, or answer why they are not addressed, or add some
> kind of TODOs so that I don't write the same comment again.

I'm sorry; They must have gotten lost in all the emails. I'll go
through them all again.
-- 
Patricia Alfonso

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKFsvUL%3DmaBVZ7v_N6W1skZRkYm4GacRGn-ohbf-o84p598XNQ%40mail.gmail.com.

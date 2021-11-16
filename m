Return-Path: <kasan-dev+bncBDEPBSN75UNRBDHVZ2GAMGQE4CHKHJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id E3C61453399
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 15:05:01 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id x9-20020a056a00188900b0049fd22b9a27sf11807842pfh.18
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 06:05:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637071500; cv=pass;
        d=google.com; s=arc-20160816;
        b=fVoCx3Khe637+nEx0LcMteP0D3xtiCZqnQ6K9aYErUsVJOEyzeA8v/HRIT39UplLF5
         oEwm+BHI1cCnZrK0qI523nr0KDkZkO1VDuBhv4U+kUUK2DhGqDC44/q9vTJuyGChqTGz
         qmvD0EzavsjGRa5UMktEkNdhffW5EOoSwepvcdfGUmiyt6f4IqOkLdEy/EkspDD0IAwo
         ZG+Dg0ePhYeUAJk155XDen+dhtjrIDcGT60emO6EKZRyVPUMj4k5vnnBcCuPZnKeMZBe
         xbU+lagu+Ig9rrnk5Y8tTSXz1ZN0SldxvoWATAVWt/IgZIdbKZFzRyrDAr6MNaHY5tLr
         +eRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:references
         :in-reply-to:user-agent:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=FRocQLuuSiJiJKuNLelkwiCApOujdieSdx/EuGiHYOc=;
        b=w1cPbbDjeoCg9ketYgfURk2KwPiVHijwepz2CcKBb2StffrCx3f4dB1H7U6bbAlKTF
         oAAU84/RoZ2uDduCN2tMpRXfOXSfKCEhmbpYeHQvoWKkOHBlQxnlXQy3LbR8QfUqjJbx
         qZCAWMI99A/FfmG/Bnf5oWI7I3ztOv0yCKWLEUwFrETuGElRAsnuSPa+ugZ2cAEW7Vi1
         j9n464H4F4MvFXXcM+DavZ8dxn47+fsHyku81HqAebsWuHC+yBxLssr/Nt17rqf6AChg
         qvClAGXNFU5VFeP9uw6mxtaLipvkRkQ8MkqhmHHXLvbpT+LLp46o4NsRB8/TFwTb6BZU
         JVWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Y8WGB5FG;
       spf=pass (google.com: domain of arnaldo.melo@gmail.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=arnaldo.melo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:user-agent:in-reply-to:references
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FRocQLuuSiJiJKuNLelkwiCApOujdieSdx/EuGiHYOc=;
        b=nBMjDeTZ7bCf5y7i5cbYg8LC/MKbEAKWlKauZzVeputIVxSYGiUVzozqROj+6t1Ltr
         nOwRfpg3nXYEPH2mA35QEByPXRernoHUTJOXC9lLeNgBDFG0GXL22NT3Ob+spjI900aw
         0XE40XJRxPRu0xxAP1J38Ib+fo9/lOwPGnYGnyPc6RRylkKS20hr1jf/FqZJThLxAbTv
         IanTL3052Y+7wWZ9pMzIGjT4SfkOXAruPPP8bdJmhbhlkkRKY/uffqmYqtLX62Z1I/6h
         Xwwqb7YI7xN75hrNARu1uy+RaaXU0v7qAI9aBIOZ23DAooHqIjoZysKUahOKew2mlFmK
         1Rkw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=date:from:to:cc:subject:user-agent:in-reply-to:references
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FRocQLuuSiJiJKuNLelkwiCApOujdieSdx/EuGiHYOc=;
        b=Scv6VHdcZpTTvv1Wcj4Wj70MkDI4PfLGgWwpN5bQyC5HUzTjxptUusZJM+PYY5xLWk
         8a596BaMlMO08ffdlPBvc2vuWj0OdJnz1PB1zvJvrnCam8UD3FfM7bjANkDwb4hNai3x
         /NTvMsA5DpwaT9iIi7HJbxE6OtBaqX9Swr2AyDDPO5lpngTqN0diJNcCJo/ve4pz5yta
         tH1nyOJpJDoTntBeZD/wTpBNYmZZbUXyt9X7J9t8gm6lh3wF4DtHtKBtthRBJPIJe+bI
         D4BtyO5THCbyRoPWDUevHPA36KA2LTtQAdwil5CCf9X91vfnQjQgnah3uFpZttxHXrkO
         qHGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:user-agent
         :in-reply-to:references:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FRocQLuuSiJiJKuNLelkwiCApOujdieSdx/EuGiHYOc=;
        b=fEIqJn0me7iGiXg8Ymvq40GAWIiONYby6hy5FNlNS6oIxEBLoIKRBnWp8sijz184Cu
         EbgkIP085XLcsZbotS0ESmfoeKkWfSOEWqLCyVgQH6UuPjPEK2VYVtd8PHVhtwoDODHy
         uLEybHCgsxUu0gYMjxnT5JlWCc7CGFi4O7vRgw6NgvPEQYg63MuiYqT+hEA5x1TPkmnX
         f+jRAgK+TnEAsZMXODUu0h3vZGrV3L84GFsE0lMwMxcOGOyr3TfdIZi8nCwByGfRes0/
         rGK2F5qqup/HIiT7t/QSGSwVsjwYul+awkbSxlZOizkguakiSBaRH/RMi8gSihDM9M/I
         9Uhg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531/PFeao319T4AbTZYX7XBYKrLTF3IeIFSkAYY80eZ4ZZHyTHJ1
	mBhUr6Rxw4DBwM4BCDuwZNE=
X-Google-Smtp-Source: ABdhPJxpd0oXWnXuFIHTMisLer9DsfRwAfA4O1UxiFIvPewF8JDxQ+32+LzCh8yCqHq+b1vS/xFU5g==
X-Received: by 2002:a17:90b:3b43:: with SMTP id ot3mr77147560pjb.205.1637071500617;
        Tue, 16 Nov 2021 06:05:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:1c2:: with SMTP id e2ls11352088plh.9.gmail; Tue, 16
 Nov 2021 06:05:00 -0800 (PST)
X-Received: by 2002:a17:90a:fd8c:: with SMTP id cx12mr74694520pjb.11.1637071497277;
        Tue, 16 Nov 2021 06:04:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637071497; cv=none;
        d=google.com; s=arc-20160816;
        b=jLpMWmBSbwvcr7wNhK1gFI1o9NJiuNxg0HoU0lLFlpnuvNva3Te0xwC2qjGT21l/HG
         QkwrchHCl6Fq68ATHImmUYhgOhhQadHW1nkoiJT4CHMq1vf9UA9i9pcD4kvmxw82kdB/
         nAMxWueCqpyTBNLL0L2JDF9SzA2KCP2lpcVznctOTuGvPip1lwjhV7JVFya1VIDB/KdE
         ePjb0CMe8/aExp1QGeqosLxnFtIYZhSd6Afg3BL9OVwebToJ+SeKL6Ya+1L4TZPWZpwx
         lA7+00eFmJtqxAtFNwu3vtpr5zr1eBz4YfBetAvetaRfG5VYAG2pFmDAsPAytO+osTG4
         ZRgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:references
         :in-reply-to:user-agent:subject:cc:to:from:date:dkim-signature;
        bh=mZinczTsHmp3D5RmZy6kAXCseVBqZP/LezZQ7PBZdU8=;
        b=RxGfGr5MuCYCIhNPUWXU5nzsWK22EbewpOKBhmp8bQZZxbCqh+5b9+Gg9yGr3HF+aw
         TCgD9dP3jPceCOtmu2tmkYSdISDVT9G9F+OOeH3+i7ZJRsetCmyamYZuA7XQQv0r3P1L
         YYRTjND/2WpSdTxHw9Bw7JHWXe5Wp5reJttsJl6L8q3oG5t+FtSPXg1h9WCUzsk3wsKh
         jzQcf9VPG+krv7L7oIU5FeNOBMLvxIJot1aO8ZKRRI6efGprAgcRI7hDJHbiKKf0PPcm
         IlJ8rZNgA3YsJlGq94tTeyojjShp8sCo/BteAkHvWoNxTRQ0leX6BFbQUMte58xnfhJa
         TKqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Y8WGB5FG;
       spf=pass (google.com: domain of arnaldo.melo@gmail.com designates 2607:f8b0:4864:20::f31 as permitted sender) smtp.mailfrom=arnaldo.melo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qv1-xf31.google.com (mail-qv1-xf31.google.com. [2607:f8b0:4864:20::f31])
        by gmr-mx.google.com with ESMTPS id c3si32910pgv.1.2021.11.16.06.04.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Nov 2021 06:04:57 -0800 (PST)
Received-SPF: pass (google.com: domain of arnaldo.melo@gmail.com designates 2607:f8b0:4864:20::f31 as permitted sender) client-ip=2607:f8b0:4864:20::f31;
Received: by mail-qv1-xf31.google.com with SMTP id kl8so9302007qvb.3
        for <kasan-dev@googlegroups.com>; Tue, 16 Nov 2021 06:04:57 -0800 (PST)
X-Received: by 2002:a05:6214:c42:: with SMTP id r2mr45911397qvj.53.1637071496430;
        Tue, 16 Nov 2021 06:04:56 -0800 (PST)
Received: from [127.0.0.1] ([179.97.37.151])
        by smtp.gmail.com with ESMTPSA id i6sm8936833qkn.26.2021.11.16.06.04.54
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Nov 2021 06:04:55 -0800 (PST)
Date: Tue, 16 Nov 2021 11:03:54 -0300
From: Arnaldo Carvalho de Melo <arnaldo.melo@gmail.com>
To: Marco Elver <elver@google.com>, Arnaldo Carvalho de Melo <acme@kernel.org>
CC: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>,
 Mark Rutland <mark.rutland@arm.com>,
 Alexander Shishkin <alexander.shishkin@linux.intel.com>,
 Jiri Olsa <jolsa@redhat.com>, Namhyung Kim <namhyung@kernel.org>,
 Adrian Hunter <adrian.hunter@intel.com>, Fabian Hemmer <copy@copy.sh>,
 Ian Rogers <irogers@google.com>, linux-kernel@vger.kernel.org,
 linux-perf-users@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH] perf test: Add basic stress test for sigtrap handling
User-Agent: K-9 Mail for Android
In-Reply-To: <YZO4zVusjQ+zu9PJ@elver.google.com>
References: <20211115112822.4077224-1-elver@google.com> <YZOpSVOCXe0zWeRs@kernel.org> <YZO4zVusjQ+zu9PJ@elver.google.com>
Message-ID: <0683D134-7465-46A8-A3FF-2E2D9131BB3D@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: arnaldo.melo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=Y8WGB5FG;       spf=pass
 (google.com: domain of arnaldo.melo@gmail.com designates 2607:f8b0:4864:20::f31
 as permitted sender) smtp.mailfrom=arnaldo.melo@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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



On November 16, 2021 10:57:33 AM GMT-03:00, Marco Elver <elver@google.com> wrote:
>On Tue, Nov 16, 2021 at 09:51AM -0300, Arnaldo Carvalho de Melo wrote:
>> Em Mon, Nov 15, 2021 at 12:28:23PM +0100, Marco Elver escreveu:
>> > Add basic stress test for sigtrap handling as a perf tool built-in test.
>> > This allows sanity checking the basic sigtrap functionality from within
>> > the perf tool.
>> 
>> Works as root:
>> 
>> [root@five ~]# perf test sigtrap
>> 73: Sigtrap                                                         : Ok
>> [root@five ~]
>> 
>> Not for !root:
>[...]
>> FAILED sys_perf_event_open(): Permission denied
>> test child finished with -1
>> ---- end ----
>> Sigtrap: FAILED!
>
>Ah, that shouldn't be the case. It's missing exclude_kernel/hv, and this
>test should work just fine as non-root. Please squash the below as well.
>Let me know if you'd like a v2.

I'll squash

>
>Ack for your change printing errors as well.
>
>Thanks,
>-- Marco
>
>------ >8 ------
>
>From: Marco Elver <elver@google.com>
>Date: Tue, 16 Nov 2021 14:52:18 +0100
>Subject: [PATCH] fixup! perf test: Add basic stress test for sigtrap handling
>
>Exclude kernel/hypervisor so the test can run as non-root.
>
>Signed-off-by: Marco Elver <elver@google.com>
>---
> tools/perf/tests/sigtrap.c | 2 ++
> 1 file changed, 2 insertions(+)
>
>diff --git a/tools/perf/tests/sigtrap.c b/tools/perf/tests/sigtrap.c
>index febfa1609356..e566f855bf74 100644
>--- a/tools/perf/tests/sigtrap.c
>+++ b/tools/perf/tests/sigtrap.c
>@@ -46,6 +46,8 @@ static struct perf_event_attr make_event_attr(void)
> 		.remove_on_exec = 1, /* Required by sigtrap. */
> 		.sigtrap	= 1, /* Request synchronous SIGTRAP on event. */
> 		.sig_data	= TEST_SIG_DATA,
>+		.exclude_kernel = 1,
>+		.exclude_hv	= 1,
> 	};
> 	return attr;
> }

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0683D134-7465-46A8-A3FF-2E2D9131BB3D%40gmail.com.

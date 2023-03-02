Return-Path: <kasan-dev+bncBCS5D2F7IUIMPRUCUADBUBCGJVZ4W@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 779076A836B
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Mar 2023 14:23:20 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id j30-20020a056512029e00b004db385ddddfsf4791974lfp.17
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Mar 2023 05:23:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677763400; cv=pass;
        d=google.com; s=arc-20160816;
        b=Wizv1ClTjw95jYpe6okc2Fs2/9xbRUp8duAyfDYmJs58Fh98Vbvwb4gj6QjjGoSZXm
         yq0E5mYarO+QQCzFSlhXSKRRiLqjPQU0eoGPQW0izEiynj8Rij73WMX/xHpBN1zOf0mh
         bwmM0gTz/Rnc4VmDrDUnTtvcjzLBmGtqyd3Kl58Cznl7p+fz1JwppYLPGL/YLptRxRjW
         qL8dMDGLh280nd2d+o2W6rIHndq+AnwAji76lo52+1jLrXDA7QAr8TyC2q78EfbGvuCn
         ZYgUssKyEgzt1bJoO9yd4SqjZas1aCvMhTu1ZICoWREwEhiA92o0yNnbHXSrmp5yUeOd
         OyTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=S/0p6Q6LGZ6xI0QAQBhfy7M7kRcJCxZfg8t+UYR/xgc=;
        b=t6LfgKBLDtkA/LasvGYT1vexUPyk/vJt0ezBZasOyemv6VbY2kuVsuxgAgo7uLOVXh
         bSZtiNTunFInNGLkPVa7mE1IAv+aFSjMXFUYMmHFek46HDSPtucGGMdiZ+BXrv+fJ/al
         EJSZwDFtqrCC7WzCnOkFUrMvMI10Jj3Zrs65eBf1zF6IPMa1foCt69Ztp8a3fksAa36S
         GauCX38cW6sHCknT10vzaWWL9UaQme0GrwLWmwoqYn9R9e473TMxDHkF7x/xPYFpt6Nt
         HbysZEGgp5yQUUsCpYoXPnUESeOSZPgj487foVzdXk9wSegiR/IeH33zdmt4iEbPNjUU
         8U4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b="q5Iqf/wv";
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=S/0p6Q6LGZ6xI0QAQBhfy7M7kRcJCxZfg8t+UYR/xgc=;
        b=VsX0+hr/eZfyeFH6xyaMuCVwJxvv4RekrgHZEijwb0puw4+BW6P6nwPYOYyfwHF94n
         PX09ADhAYpliI+oI3vzqkf8PTQgxykE9mgMsCatJDe3G8uf4XvbAVmWYL5TciRkxbG+n
         7ZWePJc3qehrISZJunzK4tiX+Ao0WQgX+qU/jb0/i5mwWM0Vr956GyDhEm7pL89ZP+CI
         XN41XQaUltLuarXAosTCzZt5ZH7L3YLtP+zUKSqbEX3ET6SjcVh1CyS6PcAM2l5LCH4W
         /Jak20LMNvANF8EABA4ZW2dEMy1hYVRdjDGuQ1AkTiotT338iOOrIxmQqf28ru3TEkY6
         2ySA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=S/0p6Q6LGZ6xI0QAQBhfy7M7kRcJCxZfg8t+UYR/xgc=;
        b=kCS6pSSLMD8Idre+oGo8tS8QOs10RIRABPdtSM1M9DmvE2NsiRVF6oamM3HiCfqxxt
         JW87AEKwleVzRki7xdmZJ+CJjBO8WBOhRX9ZsnbHwLiN61g0PPLOWZPVa9VlArXbnUbK
         H28oZXKMmtil01qsrLhA4yd92uO+Osfg1rOR32ucVIbHjJSzUGKAaU5IGItdFOXpz4mz
         UjJZO6bY1UON1iBxPtrm/iy5Nf09Spk77MR50nHeU1RWArDKamNOCRkTbf9pcIq4HQrZ
         9HlTB39I9VWrGijD0WYu07U8U93OXS24VFJVfVWLzYMfY7zhVNIvcnt9LdG1JvgfchWa
         wifw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXRg+I4phmX5/L32OzFGa46P13jrHJuQWAqxeXS5ou7utKlBUYj
	9nLCXfoR3t2UG1dtZ7bTH3g=
X-Google-Smtp-Source: AK7set/RAEqvWX6E2XdN37NSSdb2Lop8idhtPoSMT4gFJcLy+w90j2sCEmkuwHV7wxEDe50WPybzRw==
X-Received: by 2002:a2e:a4b7:0:b0:295:a8c7:4b3b with SMTP id g23-20020a2ea4b7000000b00295a8c74b3bmr3275423ljm.4.1677763399715;
        Thu, 02 Mar 2023 05:23:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3ca4:b0:4db:51a5:d2e8 with SMTP id
 h36-20020a0565123ca400b004db51a5d2e8ls5751lfv.2.-pod-prod-gmail; Thu, 02 Mar
 2023 05:23:17 -0800 (PST)
X-Received: by 2002:ac2:4831:0:b0:4de:f9af:475a with SMTP id 17-20020ac24831000000b004def9af475amr2844010lft.6.1677763397919;
        Thu, 02 Mar 2023 05:23:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677763397; cv=none;
        d=google.com; s=arc-20160816;
        b=kD8x7Awgr1Ev++AoRhXJZETMn32D9nmFYY/33txWG129u4Nxs1lDw2Dvbr9CdGQOpy
         d1eGkwPwpQdXJlIEzYhAERYQfzSgsi8cblTIE2UmrGTzrssyBZoJ+Rf+K8JpXU2FaacC
         zQKZccKfJ7xyTiyXARdojLaBNmu0/bSA+SXFfblPJX7FB+caHj0h+kzqqOZWUzWL8+Dp
         jdcIMh8hfTMUDp+Cj+/pbFyvbEWtwHLQu3AOZQFpFF8O8ebTzKsPO+qtB6uvfSphwN2Z
         8X/sgUeCBwRsiX8/eHkRKLzPLKs5uxc7n6DeA2Hn+z42MhiVY6hNLqFqG9Jwkh1yyFvL
         b19w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=MBSijBkL6qrcNLxK5wTEA5G9IQhSmVi9FlzoMJu1guM=;
        b=Zob7Wdb3LhxScDGKtcuGIkxNzU9x2il4KbGZImupdrECuPwtWcLyQ64CSnbFBwzqdi
         Hbit6KaWm7cc3BIbnNL49N+l5UsKtW1cJAGThchuWEYH+RiNhSXNE1KkKKU5jgWH3+fC
         6zMioh5PhxHQakvntbpzQOWffbl0uQV55UTIoGgtcLPw32YMoxht6kiQZPjHvgi1LyyJ
         sXyWhPDayxdYvqLbAOEdc6MQ7E/xneKInLqlk52Ymt1EKXRZXcyWR9tKbetkEr3cmXH8
         iJjCa/w1VzUbxlhaOWjtD0+y26VPuis2j1IvXJXclRMcSS6CjX/XwZXYuTQnA7wfyHV2
         URIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b="q5Iqf/wv";
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id f9-20020ac24989000000b004dc818e448asi755564lfl.3.2023.03.02.05.23.17
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 02 Mar 2023 05:23:17 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from willy by casper.infradead.org with local (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pXith-002QVV-P7; Thu, 02 Mar 2023 13:23:01 +0000
Date: Thu, 2 Mar 2023 13:23:01 +0000
From: Matthew Wilcox <willy@infradead.org>
To: syzbot <syzbot+0adf31ecbba886ab504f@syzkaller.appspotmail.com>
Cc: akpm@linux-foundation.org, davem@davemloft.net, dvyukov@google.com,
	edumazet@google.com, elver@google.com, glider@google.com,
	hdanton@sina.com, kasan-dev@googlegroups.com, kuba@kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	netdev@vger.kernel.org, pabeni@redhat.com,
	syzkaller-bugs@googlegroups.com
Subject: Re: [syzbot] [mm?] INFO: task hung in write_cache_pages (2)
Message-ID: <ZACjNSxGlVX6l39S@casper.infradead.org>
References: <000000000000e794f505f5e0029c@google.com>
 <00000000000099b9c905f5e9a820@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <00000000000099b9c905f5e9a820@google.com>
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b="q5Iqf/wv";
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=willy@infradead.org
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

On Thu, Mar 02, 2023 at 04:06:28AM -0800, syzbot wrote:
> syzbot has bisected this issue to:
> 
> commit 17bb55487988c5dac32d55a4f085e52f875f98cc
> Author: Matthew Wilcox (Oracle) <willy@infradead.org>
> Date:   Tue May 17 22:12:25 2022 +0000
> 
>     ntfs: Remove check for PageError

Syzbot has bisected to the wrong commit.  That code (a) isn't going
to be executed by this test, since it doesn't have an ntfs image and
(b) was dead.  Never could have been executed.

> bisection log:  https://syzkaller.appspot.com/x/bisect.txt?x=13fd6e54c80000
> start commit:   489fa31ea873 Merge branch 'work.misc' of git://git.kernel...
> git tree:       upstream
> final oops:     https://syzkaller.appspot.com/x/report.txt?x=10036e54c80000
> console output: https://syzkaller.appspot.com/x/log.txt?x=17fd6e54c80000
> kernel config:  https://syzkaller.appspot.com/x/.config?x=cbfa7a73c540248d
> dashboard link: https://syzkaller.appspot.com/bug?extid=0adf31ecbba886ab504f
> syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=16dc6960c80000
> C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=16f39d50c80000
> 
> Reported-by: syzbot+0adf31ecbba886ab504f@syzkaller.appspotmail.com
> Fixes: 17bb55487988 ("ntfs: Remove check for PageError")
> 
> For information about bisection process see: https://goo.gl/tpsmEJ#bisection

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZACjNSxGlVX6l39S%40casper.infradead.org.

Return-Path: <kasan-dev+bncBDDL3KWR4EBRBDM5XWBAMGQE7NJS2WA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0693D33B23D
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 13:09:51 +0100 (CET)
Received: by mail-qk1-x73b.google.com with SMTP id 130sf24316142qkm.0
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 05:09:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615810190; cv=pass;
        d=google.com; s=arc-20160816;
        b=FTQSEZRSAJw67/wZkcH7gAjxlzSxEDUuM14LCD6bnvtKHJDjbe1b51IAsJ99YDvmQZ
         0nwogHX7ZGpEDW61POoTjuBeCzpvHS1r18MICuwecLS20G6lrUw3+kIQRkUnKHHLLv0S
         lt31XU+S1fAZuscBz0XO7ByX9fIuEIZMKixYKpk5sOtAHLW2ghfG0Vlx6w+IqPOIgvke
         A4XK4ZVUc/JnmxmTobdsyWzqq1jmvFC/GjmN19VtiYl1s07hVPodrDeiCs+zT1KIDPDB
         QGaso3nEONL9w3xA7ni+MKxqL7+hb0JsNHfrZRq7OocsyJRCGSWMxlOTuBMLkpZ1X1Wl
         ZpOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=bcY2akvR/TLqdbgTpVRIAN4w52OgYnChPLSlFNORqK4=;
        b=eXpMb3TNNgRSzaAb3KYeJ1X9ik+AErOQ1P5UGdC8cmIIf+/YQUjlLLp5AKQtGgXG4X
         484ISPltmFBumPfCUwJaIwlYbFGMd5lYqxOURk6Y1mt22UvSa3/LgmReRQ0XtFDYfvcE
         Cm7O4lLINV/kf9D4qdVGatozhlSxXmVThQicHGZLg7sm62Tyw3nyHrP5nnTgKky/KzQ9
         sSb80Zpu3VfaGR2eyPQ+6VabGZk90gPJwmPlReI1IlGFVDlwSWRMS3HBs/dgQWCUjYxb
         KGj8IQm/sPVkxp9LjWQBILB0zwtiepHTIr9RsJlsuzsvS+HB3cj9mG8pBm8n4jf++EYe
         zIfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bcY2akvR/TLqdbgTpVRIAN4w52OgYnChPLSlFNORqK4=;
        b=XsM7Aj1/QC5oEQ9aT1GsV+xsDwl3YRTQWkeEqb/4hpoKlmWPh3ga0QSA9irOpQk8Yb
         PsdbEc02UxelYLJQdgKmLNUl1GHHbm5B+7tFa34z8T4t304AQOaU/CxZUrK33T0Cvvpq
         +NK0l1fVuxh3uzM2Sibnm8IYkS+a/PrvvPAGOoOZdx1afpWREydFc9y4tD/wDQZmbDG5
         pYbHlCe0+lp4Uvx7eHAiHFhGjZa4Dr90DrHV+kXGNXr4wnB4Bnn8B09eR+7EXIpXuNYt
         7QBLZBYi1PDAlZSQ785d7xRTRbNdgs1RZYJFK4GmMB5pSrxKbRwFGzarviRt9ckq+0O3
         ThJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=bcY2akvR/TLqdbgTpVRIAN4w52OgYnChPLSlFNORqK4=;
        b=mvGqhi6ezVZDeRdJxPcgjuXSxm4SKTf6TRFSxWbUt9kxqVPDVVZZWtVwQFvTncYfTV
         Do0MvpyqEr0tCoc5ZhQYfU6M7O9KoWyG5j1ir3WAmmsbWUAvTYkVpmmufvoCw+7Cz6KE
         9uff3abe2Sj/BJ89SnKCAMYvxwkrzngQz8/8tml0FB9jxLOtvgrywJCkO8LVNFn2Ftte
         Cd4xWODvNIeDKymKwJG2lKik1K1PhhPqFmZi+5TgRfUBr3NH5Ue9DhP0YIWxNQ4/o/ej
         EIoAx8/B7H1a3DyE/Kz66WfGMDbro2PNKUbtnqM5rKN2HJofCZW5KX3ly2kcLQzHJO7Z
         1QWQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532lx0kNC8K6NJFkJRCRrj830MoXxnIv/XSDRjgm09Zlg/IB3zW5
	fFs1bxSIM/XlTcTymAlsxdg=
X-Google-Smtp-Source: ABdhPJy1z/yKvOQW0SaLXoDSFE70KmEIW+APE4+JBnOAZfB86sfor00BhR+8avLYpzTICQT2Q28yFA==
X-Received: by 2002:a37:e315:: with SMTP id y21mr24812774qki.418.1615810189982;
        Mon, 15 Mar 2021 05:09:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:a050:: with SMTP id j77ls8983883qke.10.gmail; Mon, 15
 Mar 2021 05:09:49 -0700 (PDT)
X-Received: by 2002:a05:620a:146a:: with SMTP id j10mr4040171qkl.345.1615810189561;
        Mon, 15 Mar 2021 05:09:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615810189; cv=none;
        d=google.com; s=arc-20160816;
        b=NNpiS9D/JZ+6Xy2KDH2LZD2Z1oUsQQkSj2cCZD+isbuaJfubds1g/FjcjGC8taHXJC
         Hmp37xTKw4/B6ZcMvJX++nYimwsMsRiJmlRIFnBwVqdi/Wp2KphUwYx5Kj7flzEzeQTc
         ji3TbVXR5AQ+Etqz+C7RCIAIga2kiYWEJCsAJ5y4dp32XqG9vfI4mQMAwfLoz3wk9f7X
         BLaJ+s/B7l4+CxDO+S2G/cbmWmeBCfC2TLcwl3x8DABFLp4Arl8vWaVmiuhitC86RC0s
         By46JMHi9mX9SQkolMHrZTZSHGQWqF2rhA/bLaT4y1tbU2WWmBJVbCOVPHGnYMD8PJ+W
         M+2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=LdiFONlAmMyoqkhnu6hm1vFljPkjVun0N2d0Lrz3s8M=;
        b=Cs9z8sHlNerS06qsbueQD7PHZop/2hL4YKVbeXupV5eck/VgcA2qUQtdNfCLSaD4us
         nj94cPaBNSoBglm5UXDvotKJ1BLUhAyfZTgO1Q/n4TbPNSQJpp6qYtoN4QkWNSUSLgEY
         eJi11My2WEsaKobQc9RUQkfe8fXT4KuZoUZXbHlBPoofgKzK5QryVGMsabPlU+qamIAJ
         PHTcBRpVtu0Tn/o7T2DlkzBawlJbOYzms2cpaNY3v8N2Q2kdZB5NBU/iGAtMVJMxmdLD
         ZoRMcRvO26ssIaMBHIJ5HQR6ZSDMX6SvZ+t8+Wk1rFA14Sx8FZqRsFktANMmGuAcVxHk
         J96Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id o8si490241qtm.5.2021.03.15.05.09.49
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 15 Mar 2021 05:09:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id AD3DB64EB3;
	Mon, 15 Mar 2021 12:09:46 +0000 (UTC)
Date: Mon, 15 Mar 2021 12:09:44 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: syzbot <syzbot+5ecbe63baca437585bd4@syzkaller.appspotmail.com>,
	Len Brown <len.brown@intel.com>,
	LKML <linux-kernel@vger.kernel.org>, linux-pm@vger.kernel.org,
	"Rafael J. Wysocki" <rjw@rjwysocki.net>,
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Pavel Machek <pavel@ucw.cz>
Subject: Re: kernel BUG in memory_bm_free
Message-ID: <20210315120943.GB22897@arm.com>
References: <0000000000009c21de05ba6849e7@google.com>
 <CACT4Y+ZjVc+_fg+Ggx8zRWSGqzf4gmZcngBXLf_R4F-GKU4a9A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+ZjVc+_fg+Ggx8zRWSGqzf4gmZcngBXLf_R4F-GKU4a9A@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Mar 15, 2021 at 08:08:06AM +0100, Dmitry Vyukov wrote:
> On Wed, Feb 3, 2021 at 6:59 AM syzbot
> <syzbot+5ecbe63baca437585bd4@syzkaller.appspotmail.com> wrote:
> > syzbot found the following issue on:
> >
> > HEAD commit:    3aaf0a27 Merge tag 'clang-format-for-linux-v5.11-rc7' of g..
> > git tree:       upstream
> > console output: https://syzkaller.appspot.com/x/log.txt?x=17ef6108d00000
> > kernel config:  https://syzkaller.appspot.com/x/.config?x=10152c2ea16351e7
> > dashboard link: https://syzkaller.appspot.com/bug?extid=5ecbe63baca437585bd4
> > userspace arch: arm64
> >
> > Unfortunately, I don't have any reproducer for this issue yet.
> >
> > IMPORTANT: if you fix the issue, please add the following tag to the commit:
> > Reported-by: syzbot+5ecbe63baca437585bd4@syzkaller.appspotmail.com
> 
> The BUG is:
> BUG_ON(!virt_addr_valid(addr));
> 
> #syz fix: arm64: Do not pass tagged addresses to __is_lm_address()

Does this mean that commit 91cb2c8b072e ("arm64: Do not pass tagged
addresses to __is_lm_address()") fixes the regression? The patch was
merged in -5.11-rc7 I think.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210315120943.GB22897%40arm.com.

Return-Path: <kasan-dev+bncBCK2XL5R4APRBZUTT24AMGQE7DMQNDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7FC87997EA1
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Oct 2024 10:01:44 +0200 (CEST)
Received: by mail-oo1-xc3d.google.com with SMTP id 006d021491bc7-5e988a9d1c5sf1090495eaf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Oct 2024 01:01:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728547303; cv=pass;
        d=google.com; s=arc-20240605;
        b=M5gyGIpw0bJp/mOXv55i3SS7yJPlcQ9Ok/l5fMvcE18wiPWD1+nbWSQehOQx+WQmF3
         HW3XAAO7YPsIbLgtP16paBsSXXHN9CjRuNCggs+oPu0KL8MDsZbpy4f3tczQrPMvgTGX
         fGZpkOSMFUTR8swcbiyD6NHA/CIvz40gTe4bqXqpPh+F8WYIFv2b09Ay+MoheQPqk4N2
         C1C74N/jHmorxVnlfPZixx9UvmarOAwKBmRnVHSwtU3Vk0ul4Dwq703jusze0nGluYOj
         FvmrFVkT4OQGKGH5HX2HKK6OCiq8o5WFxzfdaySuSB3+6Y54TcYZ+kVz+MeTq277s5qH
         7tRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=TbSDSokPPOOEGGcjBl/Sl7yTwBgTHIn9aFSpNapl4vA=;
        fh=DlC+GAaO5rUOwht9zd0lO3QBxJ405fPdsF81ENdQCf4=;
        b=OXH9KhPgBkWEMjKvsbgvPFjvTI6jQm/IvwjIoBptr7idpBFZ6zjZjqUOo8R1rA/Vq6
         N7LtIoOXbvevxNIjacFvrUWJybkphyqpPTepN9WUHCgGyhJ6o3XLG444WAdq/6dh0Sxl
         JYAnCPb7heNeAJPazJHy324DAe1Y6ZFvtqvKn3fJ6+9Y/SGV/Rr2QasGhh2G2kwTYcDk
         YOPiGKykPaKRQcWayaMDJglsQSNlgTq2BbXeW3HBRvPXqS46K2g9UcFyv+pCJOq8k3eG
         GHLhsVzpBQL0PD0LeMTdBbT9BJnSnfeP1VqtS4D4mom4stORqTicRzPzG04RXcvg80qX
         ysCQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=ODlnf31z;
       spf=none (google.com: batv+13eeef5fd6cafc46e7de+7718+infradead.org+hch@bombadil.srs.infradead.org does not designate permitted sender hosts) smtp.mailfrom=BATV+13eeef5fd6cafc46e7de+7718+infradead.org+hch@bombadil.srs.infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728547303; x=1729152103; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=TbSDSokPPOOEGGcjBl/Sl7yTwBgTHIn9aFSpNapl4vA=;
        b=VD/8CmXLTqWeTAkc6gvRAQUSOjAGiYP3nw5aierGI5Fq9L1ufeMSurGy96HeLs1RtO
         zBIN+FOMVRhb3BVNLc+4SZ6+fvWi/oALzf0A4d5SrZrwWDZWraonBkSweRttHVazIp/s
         vOpBmD9QAF1DS56cBk10nYAo+mTnWKPnKpmftFIjjKgQd6wnvoSOGTXenlTH6VzwXb3/
         t3eYLYjK6AG2ldeLZxfBbw0XaqeW3LjWKtJgWh+lw6g1JbwAzXxBqpVN6MEEXQYBk4Z1
         zbvRq0fuB/BRIAPMGQR00Ww6xB5oBXrjCmiEY0x13gcObFB9k5ZK/p05KwRBoG4lyG/M
         Hu0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728547303; x=1729152103;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=TbSDSokPPOOEGGcjBl/Sl7yTwBgTHIn9aFSpNapl4vA=;
        b=m/LNScACecA9wSL2djeTUt+QW1GI7rqQqQAMRvPCpK/8QwVzV5cjKghJ9DUurbFmUA
         6rrURcvtzr0RxDZ1RSU6PanMjPk1/CEDHvJXKU7yU3iMyVaiJ7fgEuQGwFgWoxCjDwLx
         r9tuikD5S5R0kpqQT2GuaZZgNiKUI5weOAzp+4HlfP6mdss6fzDlZGXhQ66n0U9TYy9a
         1AQKnMBlYxkKEtStmpcwLgwtIPtQBL+wYQQ020nT5y6i68B/Hu4Yivr13Z+Y26jC6ovN
         CGf4VoRFAQbzy0ETRQsFCr6zKUBGyoOCP3Gm5uYJ5ISDN2J7ce5PzQ3b0Og4YoHRDMbI
         S3ng==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWfdaxh2JT39Ku2/t+3W3sNdoQ+gZQPNcIRhj7FHM4BpkpcKcAsnLByad0sX8axczzRnw3wWQ==@lfdr.de
X-Gm-Message-State: AOJu0YybboTI0OPkvZbFPgRE4I16F+df73xP/Ou9oCMzTffsqTxpPN32
	UsTmzm0ZAyKE5o93PfCc4QFEiesGF++Qlc93IrkIpqDhYgF18uFL
X-Google-Smtp-Source: AGHT+IHPtHK7Pv6a9URJvcylQdXBj1uOWQ659TAq63CYOjodQYCv8XQXaJylD/G32Y+laAVCENlmGw==
X-Received: by 2002:a05:6820:4514:b0:5e9:8b10:9254 with SMTP id 006d021491bc7-5e990b5e30cmr2150425eaf.2.1728547302927;
        Thu, 10 Oct 2024 01:01:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:1013:b0:5e7:a741:e22c with SMTP id
 006d021491bc7-5e990e06d62ls219167eaf.1.-pod-prod-00-us; Thu, 10 Oct 2024
 01:01:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXiwH4f2Dc7Ad9uJf79U7lqO6Xq/20wyrGDcP0SqwfeMyXaaiJsA2w+9xeCKgyxAz4XIS8qmz6rIYY=@googlegroups.com
X-Received: by 2002:a05:6871:2896:b0:270:6dfc:b140 with SMTP id 586e51a60fabf-2884d427b03mr1278786fac.16.1728547302121;
        Thu, 10 Oct 2024 01:01:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728547302; cv=none;
        d=google.com; s=arc-20240605;
        b=No/0uJ+KdblBkvbp1lHQlQbzmKQref+2MOBSN9mFsmuqCl8LZ1BEkJl3UU5VN1jhcO
         WI+yFB6Nh+yxq5v699gdPkGJvAiZUYnDBKh7hkeSOOWKx3SMbnk2etZCOHreBfaYhndA
         ufVEiipZ8XZyRbnP9CmTzBpi+afN78eG2hzLKISJN4P+acoO1yjSj2TybYHJ4m1Z1zAN
         SVvHACcpaCsMHsBbmN1YiW6/56DEkgT89mkNQ6pyOrJsbCacCzXtjp6JD2KjKErgyNaE
         dckOlvmoq+ACKOEcgMEPMiD77Msucq/ayZwgdnUStnkPZ9LUXp1PunjGP6528APyHtqX
         jyJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=3M9KdA8DamcHX+t4Rs6QLSY8A6xBoeXjIByTZaRvvrw=;
        fh=qCWKq3Q7//nrCEc94/1QX4WWdjc0EWtiYsBLzvuWTig=;
        b=N6VripItzWFj9ldLhuU/fIkeEzP/Q1FTip7Hn5QPxTQ/X84Yz0MZizyovDIzrc1x4/
         /7i/1nvxNs8/7fmwL1dWsIFp2C8z+EyYytNkkjSYIRLGBY+EvWw4J3qPCs9x5tiXunEp
         Q2bz7hlPB5fGgt70BoT7vxh5Zql+n87+pW+ywPwLlfGJ05cfC/qtmVLB2TpatxiVe67x
         Z2Kj5UNywzy7+hUAyl+McbquqcE/gd+eCriMDDi4N1mYn89mUjeFalBgMyZYmsBbAnpb
         zJiF+NymcGGTa0DCcQ/ZwxQOSDPEX6/NO+xttnJ+m2Y+Kp7id785KMUayphvMz/Q2FsB
         +0ew==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=ODlnf31z;
       spf=none (google.com: batv+13eeef5fd6cafc46e7de+7718+infradead.org+hch@bombadil.srs.infradead.org does not designate permitted sender hosts) smtp.mailfrom=BATV+13eeef5fd6cafc46e7de+7718+infradead.org+hch@bombadil.srs.infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-288584ea0casi29181fac.3.2024.10.10.01.01.40
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Oct 2024 01:01:40 -0700 (PDT)
Received-SPF: none (google.com: batv+13eeef5fd6cafc46e7de+7718+infradead.org+hch@bombadil.srs.infradead.org does not designate permitted sender hosts) client-ip=2607:7c80:54:3::133;
Received: from hch by bombadil.infradead.org with local (Exim 4.98 #2 (Red Hat Linux))
	id 1syo77-0000000BtRj-1dcm;
	Thu, 10 Oct 2024 08:01:37 +0000
Date: Thu, 10 Oct 2024 01:01:37 -0700
From: Christoph Hellwig <hch@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Christoph Hellwig <hch@infradead.org>,
	syzbot <syzbot+8a8170685a482c92e86a@syzkaller.appspotmail.com>,
	chandan.babu@oracle.com, djwong@kernel.org,
	linux-kernel@vger.kernel.org, linux-xfs@vger.kernel.org,
	syzkaller-bugs@googlegroups.com,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	Vlastimil Babka <vbabka@suse.cz>, Feng Tang <feng.tang@intel.com>
Subject: Re: [syzbot] [xfs?] KFENCE: memory corruption in xfs_idata_realloc
Message-ID: <ZweJ4UiFpOtxyeB-@infradead.org>
References: <6705c39b.050a0220.22840d.000a.GAE@google.com>
 <Zwd4vxcqoGi6Resh@infradead.org>
 <CANpmjNMV+KfJqwTgV9vZ_JSwfZfdt7oBeGUmv3+fAttxXvRXhg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMV+KfJqwTgV9vZ_JSwfZfdt7oBeGUmv3+fAttxXvRXhg@mail.gmail.com>
X-SRS-Rewrite: SMTP reverse-path rewritten from <hch@infradead.org> by bombadil.infradead.org. See http://www.infradead.org/rpr.html
X-Original-Sender: hch@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b=ODlnf31z;
       spf=none (google.com: batv+13eeef5fd6cafc46e7de+7718+infradead.org+hch@bombadil.srs.infradead.org
 does not designate permitted sender hosts) smtp.mailfrom=BATV+13eeef5fd6cafc46e7de+7718+infradead.org+hch@bombadil.srs.infradead.org
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

On Thu, Oct 10, 2024 at 09:50:06AM +0200, Marco Elver wrote:
> > I've tried to make sense of this report and failed.
> >
> > Documentation/dev-tools/kfence.rst explains these messages as:
> >
> > KFENCE also uses pattern-based redzones on the other side of an object's guard
> > page, to detect out-of-bounds writes on the unprotected side of the object.
> > These are reported on frees::
> >
> > But doesn't explain what "the other side of an object's guard page" is.
> 
> Every kfence object has a guard page right next to where it's allocated:
> 
>   [ GUARD | OBJECT + "wasted space" ]
> 
> or
> 
>   [ "wasted space" + OBJECT | GUARD ]
> 
> The GUARD is randomly on the left or right. If an OOB access straddles
> into the GUARD, we get a page fault. For objects smaller than
> page-size, there'll be some "wasted space" on the object page, which
> is on "the other side" vs. where the guard page is. If a OOB write or
> other random memory corruption doesn't hit the GUARD, but the "wasted
> space" portion next to an object that would be detected as "Corrupted
> memory" on free because the redzone pattern was likely stomped on.

Thanks!  Searching kfence.txt for random I find that explaination in
the intro now.  Can you maybe expand the section I quoted to make
this more clear, by saying something like:

KFENCE also uses pattern-based redzones on the side of the object that
is not covered by the GUARD (which is randomly allocated to either the
left or the right), to detect out-of-bounds writes there as well.
These are reported on frees::


> 
> > Either way this is in the common krealloc code, which is a bit special
> > as it uses ksize to figure out what the actual underlying allocation
> > size of an object is to make use of that.  Without understanding the
> > actual error I wonder if that's something kfence can't cope with?
> 
> krealloc + KFENCE broke in next-20241003:
> https://lore.kernel.org/all/CANpmjNM5XjwwSc8WrDE9=FGmSScftYrbsvC+db+82GaMPiQqvQ@mail.gmail.com/T/#u
> It's been removed from -next since then.
> 
> It's safe to ignore.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZweJ4UiFpOtxyeB-%40infradead.org.

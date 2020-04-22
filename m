Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBOH3QL2QKGQE7RYBOQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7AC8F1B4FAE
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Apr 2020 23:57:13 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id w70sf2911903pgw.6
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Apr 2020 14:57:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587592632; cv=pass;
        d=google.com; s=arc-20160816;
        b=KWFek7zJ0E30HbKHG289DAnvFWoE4VjSgBP/VFVBR8ekPWknR5aq+lNuDEWz6JssvF
         +BBqk1f/QmJo0Ob5EaA9WYKA7CeYsO5mpPAlqGvWJJe10fSZuNRy1W1dQS/PTGYbacA6
         r92V0Tw+lLL+yrIEnz6/mJmMrpqQFYFgVHKH0iuN/HDFWsdZyGZnYzY+2MVlfKB1EiLf
         UHdXHDCX3coGAZrFWbiqHy21fr2Ue/C4fN01bnGjh1RN7kshy6xd5Fnpn7ppl/SWz3v5
         xEYVkiFyUUcDNN8poal0apHIY6REsfM5fG78I1ARNOm+zicBAtcTlTtviK48VVPCv32r
         rDkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:in-reply-to:cc:references
         :message-id:date:subject:mime-version:from:sender:dkim-signature;
        bh=ogdSeAxOEjpbxDp7HUtddFU2+pix8IyZjjZGkg5yR04=;
        b=C1MqReBznL6lcPWtIExW8gFZgDwGHESIcnauh2ZSxBs2QmlT13qyif3Ce6JjJ/icTt
         h2+PCtQOc8zVC39+qxeJAvnl3DxRcr+nR5CN4CJKkkw2NbatdhsIPiVwp6wg0j2o5t+w
         tSYdxfoBHyTISG7S9BijhQiT2RkUBeXHDjLK8K28BOYvmowRt3Di4HDRWomTiNc/HY9P
         h2+ZpcD5BAcpFlM/Cleaf1Qs+xTGMaaixnLJvZuvKdURV2H/ZUrceZK50Ldh6fCZNfiz
         zWFEGWlIWqMVhxXwhT7jcC5lUPk+lJgYmAedxCXLApmh93rXK14Us2mNrVGoF2aQB8HY
         VoEQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b="Xkr8/aqZ";
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f32 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:mime-version:subject:date:message-id:references:cc
         :in-reply-to:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ogdSeAxOEjpbxDp7HUtddFU2+pix8IyZjjZGkg5yR04=;
        b=scu9rLn7CJoJKkRE8VFx8rNADl8pQlCKbzjJqHjvwRzaIhAErZGOVofQLF5wEcYMfy
         2P8UYh7UOF9GjEZ6mR+b3raeS2jP8j5/gjpOMxF+cJNsyjsId+qNrLtxBkPWtMyPAAn7
         NGHlzL+IMVketxldOBXjPir9UOJufh93lrJKzvzTruav2bYYKk6BYF8Xitc5Wn/vNXTY
         an67UQMTrgtkJehisaP5irpyv5AvOl4Vy6lnbwSxuxYWtr2+hgtDKDruazAon6fiRXID
         5/g+m1KtXFyxohMGiDC9ZUFFKrEHknAJS0lqsYim0HrSWeejml9KgxvWrnnSJN8kLqy6
         KQ8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:mime-version:subject:date:message-id
         :references:cc:in-reply-to:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ogdSeAxOEjpbxDp7HUtddFU2+pix8IyZjjZGkg5yR04=;
        b=t7rUnX69pnXAm83y4Xn76Draj7ODxY+D0jJhBl3OsZDNOyqH+e1DNIwAnLfvYYYA11
         TC3d9bjKaBS39zhHRsToZZOhsAzkFWX5xnlnsjIFgmzBhoVFe0IWT833JdNX0SJGzEEv
         eNFlF+yQGA2NjVJr6I/Sb+EeY5mBm9mXqVeoGIcannqdMWp05jRM4zptO5sGbzCN8pyj
         5nximidz5los4uqN0BcAxBFKeJRy8MpOJM2atUs1irXyHN2R/fD97/Q5bLkOuqPIDHTh
         oGgT4aEPoc/83nrZGvfMt/6AXMlrVXP39mXZ9+KV+ax4642KqMa+WW2AYXMFQHGYahu2
         RGfw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZnfdmjWAYIa61chwV2NGV4F1L/CJXCihGkUTElV6aDAGtuWvIh
	y7WpqF+ZGd4PypN5Z6O0QOw=
X-Google-Smtp-Source: APiQypJQ89dKSA1t9o8X7fssPZ8t3UjdmT+NYvqhuFK+pnL2kVWsIOrKOUzoi7fDPatwtcv6rwc4IA==
X-Received: by 2002:a62:6341:: with SMTP id x62mr607389pfb.289.1587592632183;
        Wed, 22 Apr 2020 14:57:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8a98:: with SMTP id x24ls1975789pjn.0.gmail; Wed, 22
 Apr 2020 14:57:11 -0700 (PDT)
X-Received: by 2002:a17:902:8608:: with SMTP id f8mr794805plo.110.1587592631679;
        Wed, 22 Apr 2020 14:57:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587592631; cv=none;
        d=google.com; s=arc-20160816;
        b=B77DYFmutOoVeIHU/A1oc+nwK04Q4w42Vclh+5QYfl6nSXGBySXEUhWQutBD1FjwNV
         VQNe7Sd4IMJMhqvN4GZnUKj1TwZUas/8mRluFkA0zKWz1BrGYgja72wisx2oHfaElbPl
         65IxBAfEcxjMQBRdZ7jJ3eG6/BbBU/Anr0RUOPlZbSNwKLFXopf+1plEXCNOhZwM2QSV
         GMQ3g8RmiVA9wDqmLkeVJAsgkfzF+ITZB8nESQonJ3LqEZfewbpJ+0FKir0fN4cLa41o
         IX6m2JdpDhrt/lpdwwTtBJ5lJBIvURimXRQSf66S79CFRMBRti1XTwaOhdEul8sqFE/c
         Ttcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:in-reply-to:cc:references:message-id:date:subject:mime-version
         :from:content-transfer-encoding:dkim-signature;
        bh=bCYSbrkAcLApqeSJQeNPRxPOgdiEgxapSs/4LEPZeLo=;
        b=R9Q220Nf2LXhDuR+N2j2Te7wIVBqoiqQvBL+zBAUwyxow1PDdx5IdsjQ4CJEW4+les
         jQ784DKhJmf+6+NLMmgOmU+4y1udXXCsYt5hzuP/0Fea3Si38W2dby9KHP87f0IgMQdT
         bvaTJA9ihqFgIVidSrcFyd73jzf1X/EILrhUq9K4Cbs7dm3Lc1eg47/NqlXa3RUyhcXW
         EerNb79sLozKXYxQQMydxtEhPZx9VxCIOPPG5cQAfyZwwdYchYMDPJnjFeykeohiT7B0
         kzryhYiazGLYkGjg/XcFroE3h3PiQMUw9cBA5pWr52P0PuZxfEZfVmbfLMF2C2Etvpte
         ns/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b="Xkr8/aqZ";
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f32 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qv1-xf32.google.com (mail-qv1-xf32.google.com. [2607:f8b0:4864:20::f32])
        by gmr-mx.google.com with ESMTPS id c1si85167pgd.4.2020.04.22.14.57.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 22 Apr 2020 14:57:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f32 as permitted sender) client-ip=2607:f8b0:4864:20::f32;
Received: by mail-qv1-xf32.google.com with SMTP id v10so1814028qvr.2
        for <kasan-dev@googlegroups.com>; Wed, 22 Apr 2020 14:57:11 -0700 (PDT)
X-Received: by 2002:a0c:facb:: with SMTP id p11mr1166011qvo.17.1587592631204;
        Wed, 22 Apr 2020 14:57:11 -0700 (PDT)
Received: from [192.168.1.183] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id 190sm329630qkj.87.2020.04.22.14.57.10
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 22 Apr 2020 14:57:10 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
From: Qian Cai <cai@lca.pw>
Mime-Version: 1.0 (1.0)
Subject: Re: AMD boot woe due to "x86/mm: Cleanup pgprot_4k_2_large() and pgprot_large_2_4k()"
Date: Wed, 22 Apr 2020 17:57:09 -0400
Message-Id: <462564C5-1F0F-4635-AAB8-7629A6379425@lca.pw>
References: <20200422214751.GJ26846@zn.tnic>
Cc: Christoph Hellwig <hch@lst.de>, Borislav Petkov <bp@suse.de>,
 "Peter Zijlstra (Intel)" <peterz@infradead.org>, x86 <x86@kernel.org>,
 LKML <linux-kernel@vger.kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>
In-Reply-To: <20200422214751.GJ26846@zn.tnic>
To: Borislav Petkov <bp@alien8.de>
X-Mailer: iPhone Mail (17D50)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b="Xkr8/aqZ";       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f32 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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



> On Apr 22, 2020, at 5:47 PM, Borislav Petkov <bp@alien8.de> wrote:
> 
> Very good catch - that's one nasty wrongly placed closing bracket!
> pmd_set_huge() has it correct.
> 
> Mind sending a proper patch?

I thought Christ is going to send some minor updates anyway, so it may be better for him to include this one together? Otherwise, I am fine to send this one standalone.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/462564C5-1F0F-4635-AAB8-7629A6379425%40lca.pw.

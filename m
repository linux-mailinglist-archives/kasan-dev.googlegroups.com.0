Return-Path: <kasan-dev+bncBCMIZB7QWENRB7X4ZOBAMGQEMO3JDJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id B212B340019
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Mar 2021 08:17:19 +0100 (CET)
Received: by mail-ot1-x33e.google.com with SMTP id 81sf1869960otc.15
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Mar 2021 00:17:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616051838; cv=pass;
        d=google.com; s=arc-20160816;
        b=CRu1T7Chiar3bLKcTsMQLIz6JRCDYeMBCC4Q2U0pjVOpxvVPBF5e4HeScVLiz44lvh
         iszkVLb2Kdr+ubaF2iNEjvO/1Q97S4G57FkzQ0VGBIh8vJ3ulwsjOnWXr61x4lVMciRw
         ebvjn6Fow+lOE0yyOWk7+/UxZSY9kX7yFsYYPoolaWwoI/peJU2VpErLm5++4o20VgUF
         dp4X0SRJPcPOC3zEC0ctjrSm2CkfvXAjFs4nwzJCLPc7o/7gj0WrW325OabIzf/mULmU
         UC57TSfXneOQllSFU5W5e9FqcIujpO4oQFRV15q551TSO24epi3xPebnTjN+ok7AAnzF
         HvJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=AiYO1jcqS55P42oIGFuivUctU/PEWj6C1uEUb6wHzS4=;
        b=HHfQWrrMj7cXBmzRMKjD+xMZPx3VMrjmmT2ohQ3EU80Pkn66vZ7MgJYo+xpZajeWGM
         8WVcbkL3wEqOYEteEgJ69Hs32IJYCaqPrp5RCQn6cu9+yVENkZAdarkYGcVcZlUXaL1J
         s9Pgs/bkMusiL52CgFByl6xtpts/oGXgpy30K6c4kJj8ly54IEWS4/Dd70s9XHAfp+a5
         9jRroLtMY9/+6lJxE892shFda9GGjTCHxs6+rb0SRTvGKBtnOrpjdSJ2xUR/y1pgRogv
         VGNrRgKwMZibR5EtUNxOjG25UXt0OpAuBySj1EXppZdtREdz/p4eMnPwdBOSm+GhGsTT
         q8EA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="N57/fquy";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::836 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AiYO1jcqS55P42oIGFuivUctU/PEWj6C1uEUb6wHzS4=;
        b=kpHAa2iCN1LYrD7WsUr6Gv86TTRVZWG/hVRGK9s+G36s7rEpOLLxBBGd+LSqqaFLr2
         A3YxMrYuPGm57NSylXSc4oQTTcdm1nK3qm+U/EdLiD4fgbEqW4gb3dn4EDF7o3OYKPpV
         D91EgEBs9LI0i/nSFqX3acq5azI0F80DwlsoOflZlB7HOgPTFc+B6NDmsUYA/XbKHMHR
         S3tM7HxrbUUSbUKT7efSdsz1DRdzZjd5asq+kLdWsbKMjn5LeC44mIXrxS7nUu6beW7N
         1z+PXYXt9SBFfoJOog98NXlY+6w4qUqV4UskbU5hfbj+3kPAOvQH+Pwwq3wVDhAKFumH
         /Lvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AiYO1jcqS55P42oIGFuivUctU/PEWj6C1uEUb6wHzS4=;
        b=n9vkOdDphuM8tGTGqY691kK2KDDQcZaGbJ9CzD2J86wdrQTGV13+lIt4NLfKJB5cnD
         XBwyNDQu3iauFmBNs2YW88Mdqy89l7+tqYN0cldpqVHdOhpOndE6t8wyhuxCk9flCMKi
         3r8QX6+V7tEbjWo44AkBJ5D6+bsY0nFlhsfhF9DcrUV1/X29itAXnMS8+ckLqhoZvUVP
         9zo3cRuJIB2Oo+Z+ChW0eb2/eHSjct/wt8SNu5nbSvQMAzaeQYjvXRV5DBH1rynVsDp6
         EEtdtjQj2hP4Yje4SGAKCf4bKxb5W3xjkOmmXt9Tn6vMsDEJKmA2pPl1cwkuJX/zrCV6
         3q1Q==
X-Gm-Message-State: AOAM530vfJ24GTH8nnbcybA10uUIsi8bpj2snrhAnTi/c9V30r9okpun
	MTaBSIxwP5/AYBVdqLS6uYw=
X-Google-Smtp-Source: ABdhPJy1hXTgXH0bTMqNmc1Gi+EkWYFTrTiXBwCsLWbQJehtHG6+mrJdkMSbCtNCuJtQ+8s49VWtmw==
X-Received: by 2002:a9d:4e05:: with SMTP id p5mr6424886otf.264.1616051838384;
        Thu, 18 Mar 2021 00:17:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:12f2:: with SMTP id g105ls279775otg.6.gmail; Thu, 18 Mar
 2021 00:17:18 -0700 (PDT)
X-Received: by 2002:a9d:2f65:: with SMTP id h92mr6494541otb.327.1616051838039;
        Thu, 18 Mar 2021 00:17:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616051838; cv=none;
        d=google.com; s=arc-20160816;
        b=BKArttm9G+u9JEx336pBdIWoCFclQXnCWI0NTOCAcFSsFc4Evha6Wpi3RJAsQP+gJ5
         Q04PfMkIx/w9o/3ef6SLfDbUqiJFSjzdQb+meux0tU8cUOL7CeBIc6t/tyK5exkYlJJD
         HJGlcEYh+jG3+GaEnT6aBrv2gXzd2G/kIWA8MyYgYNPAMxOvuqp2mfSnt3t3S9Jau9du
         kDh4a5orp4XsG7SLJkU3WwkmZdMBcxiq1VEokZ8v5EAtv4Dn2OOL9XCjFCEqW6kTjmsn
         iI9naV06zLKZ7R/t38ez8vr2y+MqrQPcJHJTjyW7Vxg67tdQ9zi8A0itukzY2kxl3wY3
         I49w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=agahROSdNuYhnd8y/3W/h5Jobfh9gncs4vepyfROKvE=;
        b=tuKNfp/W1RGFZgWVoEqX7USDeXI1oupsOnpLc1On+YnjzOKBfH/YWKz89cBfdjPasg
         criqnhymAMT73lqzxlYHMoJUFzk4FF6BGdNUS913VixF2DsVm6CdUxCUFvSsEi+H0Q1Z
         ggmgwb2T9hhlzMBGDD3C2jYxJSS80zHaKpPk6U2uoOTtKAB6Q2Eb/XV+PY5Uz+tqfTtR
         cJj8NRf9OB0OTk7v1834Npuu8wtFSvqoRn47WmRiK4wFJnN0u/NdwJUn7pOJspVz7iw8
         LXtrBS7amm/px3kEFbV0itF20/OfgEygDw2BPStLxsmjn4+TYYGYygdlx/pluZaf9n1C
         8fPA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="N57/fquy";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::836 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x836.google.com (mail-qt1-x836.google.com. [2607:f8b0:4864:20::836])
        by gmr-mx.google.com with ESMTPS id y26si103064ooy.1.2021.03.18.00.17.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Mar 2021 00:17:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::836 as permitted sender) client-ip=2607:f8b0:4864:20::836;
Received: by mail-qt1-x836.google.com with SMTP id r14so3361579qtt.7
        for <kasan-dev@googlegroups.com>; Thu, 18 Mar 2021 00:17:18 -0700 (PDT)
X-Received: by 2002:aed:2c61:: with SMTP id f88mr2438071qtd.337.1616051837341;
 Thu, 18 Mar 2021 00:17:17 -0700 (PDT)
MIME-Version: 1.0
References: <20210211080716.80982-1-info@alexander-lochmann.de>
 <CACT4Y+YwRE=YNQYmQ=7RWde33830YOYr5pEAoYbrofY2JG43MA@mail.gmail.com>
 <01a9177f-bfd5-251a-758f-d3c68bafd0cf@alexander-lochmann.de>
 <CACT4Y+ZPX43ihuL0TCiCY-ZNa4RmfwuieLb1XUDJEa4tELsUsQ@mail.gmail.com> <46db8e40-b3b6-370c-98fe-37610b789596@alexander-lochmann.de>
In-Reply-To: <46db8e40-b3b6-370c-98fe-37610b789596@alexander-lochmann.de>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 18 Mar 2021 08:17:06 +0100
Message-ID: <CACT4Y+bdXrFoL1Z_h5s+5YzPZiazkyr2koNvfw9xNYEM69TSvg@mail.gmail.com>
Subject: Re: [PATCH] KCOV: Introduced tracing unique covered PCs
To: Alexander Lochmann <info@alexander-lochmann.de>
Cc: Andrey Konovalov <andreyknvl@google.com>, Jonathan Corbet <corbet@lwn.net>, 
	Andrew Morton <akpm@linux-foundation.org>, Wei Yongjun <weiyongjun1@huawei.com>, 
	Maciej Grochowski <maciej.grochowski@pm.me>, kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	syzkaller <syzkaller@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="N57/fquy";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::836
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Wed, Mar 17, 2021 at 10:10 PM Alexander Lochmann
<info@alexander-lochmann.de> wrote:
> On 15.03.21 09:02, Dmitry Vyukov wrote:
> >>> Does this introduce an additional real of t->kcov_mode?
> >>> If yes, please reuse the value read in check_kcov_mode.
> >> Okay. How do I get that value from check_kcov_mode() to the caller?
> >> Shall I add an additional parameter to check_kcov_mode()?
> >
> > Yes, I would try to add an additional pointer parameter for mode. I
> > think after inlining the compiler should be able to regestrize it.
> First, I'll go for the extra argument. However, the compiler doesn't
> seem to inline check_kcov_mode(). Can I enforce inlining?
> I'm using GCC 9.3 on Debian Testing.

That's very strange and wrong. Maybe you use something like
CONFIG_CC_OPTIMIZE_FOR_SIZE=y?

With gcc-10 I am getting:

ffffffff81529ba0 <__sanitizer_cov_trace_pc>:
ffffffff81529ba0:       65 8b 05 59 53 af 7e    mov
%gs:0x7eaf5359(%rip),%eax        # 1ef00 <__preempt_count>
ffffffff81529ba7:       89 c1                   mov    %eax,%ecx
ffffffff81529ba9:       48 8b 34 24             mov    (%rsp),%rsi
ffffffff81529bad:       81 e1 00 01 00 00       and    $0x100,%ecx
ffffffff81529bb3:       65 48 8b 14 25 40 ef    mov    %gs:0x1ef40,%rdx
ffffffff81529bba:       01 00
ffffffff81529bbc:       a9 00 01 ff 00          test   $0xff0100,%eax
ffffffff81529bc1:       74 0e                   je
ffffffff81529bd1 <__sanitizer_cov_trace_pc+0x31>
ffffffff81529bc3:       85 c9                   test   %ecx,%ecx
ffffffff81529bc5:       74 35                   je
ffffffff81529bfc <__sanitizer_cov_trace_pc+0x5c>
ffffffff81529bc7:       8b 82 d4 14 00 00       mov    0x14d4(%rdx),%eax
ffffffff81529bcd:       85 c0                   test   %eax,%eax
ffffffff81529bcf:       74 2b                   je
ffffffff81529bfc <__sanitizer_cov_trace_pc+0x5c>
ffffffff81529bd1:       8b 82 b0 14 00 00       mov    0x14b0(%rdx),%eax
ffffffff81529bd7:       83 f8 02                cmp    $0x2,%eax
ffffffff81529bda:       75 20                   jne
ffffffff81529bfc <__sanitizer_cov_trace_pc+0x5c>
ffffffff81529bdc:       48 8b 8a b8 14 00 00    mov    0x14b8(%rdx),%rcx
ffffffff81529be3:       8b 92 b4 14 00 00       mov    0x14b4(%rdx),%edx
ffffffff81529be9:       48 8b 01                mov    (%rcx),%rax
ffffffff81529bec:       48 83 c0 01             add    $0x1,%rax
ffffffff81529bf0:       48 39 c2                cmp    %rax,%rdx
ffffffff81529bf3:       76 07                   jbe
ffffffff81529bfc <__sanitizer_cov_trace_pc+0x5c>
ffffffff81529bf5:       48 89 34 c1             mov    %rsi,(%rcx,%rax,8)
ffffffff81529bf9:       48 89 01                mov    %rax,(%rcx)
ffffffff81529bfc:       c3                      retq

Oh, wait gcc-9 indeed does not inline:

0000000000000070 <__sanitizer_cov_trace_pc>:
      70:       65 48 8b 0c 25 00 00    mov    %gs:0x0,%rcx
      77:       00 00
      79:       bf 02 00 00 00          mov    $0x2,%edi
      7e:       48 89 ce                mov    %rcx,%rsi
      81:       4c 8b 04 24             mov    (%rsp),%r8
      85:       e8 76 ff ff ff          callq  0 <check_kcov_mode>
      8a:       84 c0                   test   %al,%al
      8c:       74 20                   je     ae
<__sanitizer_cov_trace_pc+0x3e>
      8e:       48 8b 91 b8 14 00 00    mov    0x14b8(%rcx),%rdx
      95:       8b 89 b4 14 00 00       mov    0x14b4(%rcx),%ecx
      9b:       48 8b 02                mov    (%rdx),%rax
      9e:       48 83 c0 01             add    $0x1,%rax
      a2:       48 39 c1                cmp    %rax,%rcx
      a5:       76 07                   jbe    ae
<__sanitizer_cov_trace_pc+0x3e>
      a7:       4c 89 04 c2             mov    %r8,(%rdx,%rax,8)
      ab:       48 89 02                mov    %rax,(%rdx)
      ae:       c3                      retq

This looks like a bug in gcc-8/9. gcc-6 inlines again as well as
clang-11/12 inline.

Please add __always_inline for check_kcov_mode.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbdXrFoL1Z_h5s%2B5YzPZiazkyr2koNvfw9xNYEM69TSvg%40mail.gmail.com.

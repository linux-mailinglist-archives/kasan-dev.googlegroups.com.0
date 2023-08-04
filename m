Return-Path: <kasan-dev+bncBD7I3CGX5IPRBE4NWOTAMGQENB6YPZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id C261C76FD70
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Aug 2023 11:36:20 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-2b9b2fb9770sf19956011fa.0
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Aug 2023 02:36:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691141780; cv=pass;
        d=google.com; s=arc-20160816;
        b=vrVOqGiENW4WyJFMhS0eJgqbVjgIupcYovIPTC6767r3HnklfstIsrQoRGvcbFUDDY
         gXuwOpgz5aB6U4FpbqbI/vtQht7QEl6yX71DIJyUzH66iABSQJQucu8bKQcfScWP1DZJ
         Dilfll7tcjAIjos8xbsaePMt60T1wALsaSLiNHirlRAS30ZgBdBrx0hApDnyiE4C1oK6
         qz5B8D5K4bhiXDHhqe3cl2liHKP10iMPYO/+kcpajcKrYb1cCQpUA7IwCIdQcHSPCqCk
         u7BUnhohr1hGf92Ww/QI+AHG5TJqh1E10tZq3kPcNUe+uZhXBGpfm7V1n23pgkeH29Yv
         mXFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=BrVFbRF8hKCGvas8og6+yiqKDdZ0CMKxWnNUdUGUOTo=;
        fh=Al7vh/+j54dCP9T4Q/KoT2/pH0X7zpBvlgRVzT1f1/0=;
        b=swaA/vJuxoKKkFiYOjJAeD4Jc5DgMYXjtd/UfurVtL1qyNsNTloq6Q8bTKTEs/v4l7
         vMsxd/pIX+8OeVdwMRBxfN4IA89F3qaRX24BkgShlr55gfzAZzke9K8RwVOI6DdhLU2C
         vgm0cWUjApKKOotm/Mva78xyAcd+KWrATp+slXl/X+skc1rmP5Z/D44NhSc5nPxbr8aE
         tA8kPXZwAn/4m+bIs9XybwjSOAB/CKGAjBitUPQF171D04bRSpesivEakwIJBsfpuYs5
         JZnTAmn1DW5CCPhL9k23OBUZXxmeIBNeiCOsDyzEgcHLMA/k4uznWEkEzedMPJRRVO6c
         Ds7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rasmusvillemoes.dk header.s=google header.b=VOaKqkAf;
       spf=pass (google.com: domain of linux@rasmusvillemoes.dk designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=linux@rasmusvillemoes.dk
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691141780; x=1691746580;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=BrVFbRF8hKCGvas8og6+yiqKDdZ0CMKxWnNUdUGUOTo=;
        b=XE9CXLRbNAC3vJDQM4lJ/YsJgcnTtIrXv5iZF0TwFD+JHMKVphlNGdljudb34tM+S9
         mbdMMLjQF+ENlJh5MA9gYT4qarHsCeQH+JfbOQ/INzu1A7okd0WPCiJznHuj8aW058l5
         47Tg3fPQBLhNJa7unFWLFFbN96oVae54fyMYIsQKqt9bOPBxA7lqhuXw9WPY9Wjh/iNL
         xuUoFLjCFqClEF5MZLbTT3COdd03eHKUZvuNc1YWIJ9Q2HkFm4196z3gbCiaOoy39fP9
         1FSjv9MLsFjRl/D2X/VyaNaIHwNO4rAzY8nefQNFBeyhBae6Z5OfwXyLkBANx5xrk72R
         baGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691141780; x=1691746580;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=BrVFbRF8hKCGvas8og6+yiqKDdZ0CMKxWnNUdUGUOTo=;
        b=GMnGC70xWaBuVKc/52m/vfCi5FX9uLrRSLfqe9SBpAcT5u7sD7h1DIjHeCN9y5Iq+V
         x33HOQKc6pDDZ6rUBQnbZCQdSH6PG+Ao6Cj8px0c7xZ80H29GUzDAFPzij4C3pWizVmL
         7R6pjPFBTiMG4symzTZUNif+6dveL1YQfaWJnCz9G8WSXMT8s4sIN2cVSs0Qk8dKX9TJ
         ZNhaqE1LI3N2K5BZP3mFH1kx6IqJt4aLiJu+dHcbmn1w4Xe9sUln7b2CuuqC8SavUWaM
         haNdeFu+Y01K+bKUD6wUED71YDU0voLns9BOxpc/C1OtFp0QnV++3PEUGVXEOtmoMjV2
         WL1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy12fidPpI8stt6EmyC6hKUn9Lo58CvfPEx8OfSC8RbNIQ4gk/e
	HUTvssUz6S0ORNf9JB1xaBg=
X-Google-Smtp-Source: AGHT+IEcEzmsy26gRlw0GTyuQNxzb3JQVwPXG1S6b4F6LJ1dD6niUOqs6ZiBpNuRs5Elg9Cg54oHlg==
X-Received: by 2002:a2e:9dca:0:b0:2b6:a3a0:5f7 with SMTP id x10-20020a2e9dca000000b002b6a3a005f7mr1209050ljj.9.1691141779314;
        Fri, 04 Aug 2023 02:36:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc1d:0:b0:2b9:6182:b0a4 with SMTP id b29-20020a2ebc1d000000b002b96182b0a4ls861423ljf.2.-pod-prod-05-eu;
 Fri, 04 Aug 2023 02:36:17 -0700 (PDT)
X-Received: by 2002:a05:6512:3766:b0:4fb:52a3:e809 with SMTP id z6-20020a056512376600b004fb52a3e809mr727773lft.28.1691141777558;
        Fri, 04 Aug 2023 02:36:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691141777; cv=none;
        d=google.com; s=arc-20160816;
        b=t9RzaDsrNk14S3xAIpN2zzU3EoPXNfJQLtynyyP1eN9+araVkrK/Ph7GLc9kwXM0Pe
         gSkNth3nRVmX+UFDZHR8890X9iFkcvkFJcfDTzzvW6MAmmMOmaHpcm4+tUZGrmOgURba
         zc0xZ7nQe4BpUvZHL96emGfCcZ9vfzmX6br7QKvJNaNUjGwKnMNoFLIizMdRB5zgjuJ5
         4l0DJ0d15uZHNPbDV5IDweQzACrXLf9V5FZB8vexZr4U70LPnBSql12WF/a99AWj+gC+
         wLvwh+O57pl1pP4mSnLodiHBL0y5UeaMeAMKGbjrVel2CI73MGYop3jiMJJYSa/jXKQ6
         HTMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=b3lbJTLxyqYJX0fxtiEjE0xWQWcO772B/HmxfLlMWGA=;
        fh=Al7vh/+j54dCP9T4Q/KoT2/pH0X7zpBvlgRVzT1f1/0=;
        b=OtkLXo0+coh/n1mlliMGVQkVcRwTu/l26/fti27QtEcyuLFPrjYe6HPocXCJfgv1EG
         OzZGp6loQhUxjLlz6r5aGc5bX1+yNmhOipYLcInlIIEsAxJIztwT79J5nRpEz6c/Tr47
         2Lqs4qOsoaSDq0uXOg/jso8WXEoBKv6pfZYT3CTpGBQeWtoHISBaLuuN4cSvwez4e3N3
         yU6YHIl/5SU/zFDrAN3IrVm7xqAIStbrideZkNZYOUOfbVhxR6Pps7b5OLJJNegX1ggU
         /M5rClSo2W9qS+yxOvaITfRPteiBtMdicqC/09N9HOnZclPRFYxeeWUOTLW7s+mwv4Hp
         LMTg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rasmusvillemoes.dk header.s=google header.b=VOaKqkAf;
       spf=pass (google.com: domain of linux@rasmusvillemoes.dk designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=linux@rasmusvillemoes.dk
Received: from mail-lf1-x132.google.com (mail-lf1-x132.google.com. [2a00:1450:4864:20::132])
        by gmr-mx.google.com with ESMTPS id q18-20020a056512211200b004f8621b17fasi128585lfr.3.2023.08.04.02.36.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Aug 2023 02:36:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of linux@rasmusvillemoes.dk designates 2a00:1450:4864:20::132 as permitted sender) client-ip=2a00:1450:4864:20::132;
Received: by mail-lf1-x132.google.com with SMTP id 2adb3069b0e04-4fe2de785e7so3289560e87.1
        for <kasan-dev@googlegroups.com>; Fri, 04 Aug 2023 02:36:17 -0700 (PDT)
X-Received: by 2002:ac2:4eca:0:b0:4fd:d9e0:4d79 with SMTP id p10-20020ac24eca000000b004fdd9e04d79mr801440lfr.6.1691141777216;
        Fri, 04 Aug 2023 02:36:17 -0700 (PDT)
Received: from [172.16.11.116] ([81.216.59.226])
        by smtp.gmail.com with ESMTPSA id i13-20020ac2522d000000b004fe461aab36sm303606lfl.129.2023.08.04.02.36.16
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Aug 2023 02:36:16 -0700 (PDT)
Message-ID: <33e128e8-9330-c73e-4c55-e56cbc87450a@rasmusvillemoes.dk>
Date: Fri, 4 Aug 2023 11:36:15 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.11.0
Subject: Re: [PATCH v1 3/4] lib/vsprintf: Remove implied inclusions
Content-Language: en-US, da
To: Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
 Marco Elver <elver@google.com>, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org
Cc: Petr Mladek <pmladek@suse.com>, Steven Rostedt <rostedt@goodmis.org>,
 Sergey Senozhatsky <senozhatsky@chromium.org>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrew Morton <akpm@linux-foundation.org>
References: <20230804082619.61833-1-andriy.shevchenko@linux.intel.com>
 <20230804082619.61833-4-andriy.shevchenko@linux.intel.com>
From: Rasmus Villemoes <linux@rasmusvillemoes.dk>
In-Reply-To: <20230804082619.61833-4-andriy.shevchenko@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linux@rasmusvillemoes.dk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rasmusvillemoes.dk header.s=google header.b=VOaKqkAf;
       spf=pass (google.com: domain of linux@rasmusvillemoes.dk designates
 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=linux@rasmusvillemoes.dk
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

On 04/08/2023 10.26, Andy Shevchenko wrote:
> Remove inclusions that are implied and guaranteed to be provided by others:
> 
>   compiler.h	by types.h
>   string.hi	by string_helpers.h

What? No. That's not what we want. Each .c and each .h file should
include the headers that declare the stuff they're using. So if
string_helpers.h magically stops referring to anything from string.h,
one should be allowed to stop including string.h from string_helpers.h.

Sure, those two may forever be so intertwined that it never happens, but
one really can't maintain some matrix of "X always includes Y so if you
include X you don't have to include Y" in one's head.

Rasmus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/33e128e8-9330-c73e-4c55-e56cbc87450a%40rasmusvillemoes.dk.

Return-Path: <kasan-dev+bncBD52JJ7JXILRBAF24GPQMGQEXBA4NKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id E48F86A16B6
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Feb 2023 07:45:21 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id n27-20020a05600c3b9b00b003e9ca0f4677sf638276wms.8
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Feb 2023 22:45:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677221121; cv=pass;
        d=google.com; s=arc-20160816;
        b=LkM/4j0hY7vU3YFly+P3fsnFkQZBN/zfSL+EfAcXvANEWjAUPo4pSssgTRQ04pk9ay
         k+9UzPw5REAoGqgoC+fkdK4RTLy0w9/xeX/9PfcTb/aftc+YYC9ydHUmy2bhfUStTbQR
         6Jg+AXCxIxjcEktdKyYKLFLZKa50rSyAXoFz2E/gk24QtmwU7FeOD3Gj9IQeUe9ddEyP
         4YFdm4rTJ0n5b85gwL7TgGr/KsXbLYSE4sCarUNvfoxTzZOVLdZm6kR2K2ct/0kKW24T
         hz0rA7dBe4bPbgsUCSqQhxrwdePMT3PSq1EfSIu/ipfcGwVTsLmaVXaAZPboUTytesJw
         Baww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=LCg4Gg9oRGRiXhW1Qi6ITGJ5RJILT70VyDqMKTSz9SQ=;
        b=Zh4A6HEK2XqFdCHTemF6MYU9B0mKGnIntcSe2tVHcuNPr751P/JAKuAlEBb3DGNCnF
         IX5Rb1yg2nsS3wqeDfkDqqZy52crVhN/OOYmHtHtPS21kHjFD1SVpFSpllc3t2ZsC+1G
         yu8e+zKubLEl4592FTLTHWZlYg2mVFZRfCxc6Q3a3/KsTk7dtVnt3EjwAcyffowScw92
         Hx2dQZyrAJlFOjKaVoelVfHeWufEGjFE1Xwhz9nltCDIQb2lVNwsWf5QOkCbJNCRXKny
         6ZkSSNrN8XUfPZwAjI3xxOH0n/jtfK+xWNUSRDrtWyjw54vQSzHbTmXvBjwn6uIU7ez4
         YiOQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=N39tkFtx;
       spf=pass (google.com: domain of pcc@google.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LCg4Gg9oRGRiXhW1Qi6ITGJ5RJILT70VyDqMKTSz9SQ=;
        b=myadThGVjd17VJUvNn01ekjB6NsLQz8sm9v/1Vt5wm6gsccG1pEeR0/eLT6ufEzcxU
         RUjjGykcmD55TkV0vYxGvm3GBSKvbxf2McMEu3NExhq78hHyCqVM/LtVTcbFdDS/MGnW
         BwneTCsyypfAsA7WdxBv7ULrlv83gcC3PX0ZEU4weXGHefBac6e3U/m+1TfmNxlEDhgt
         218+m9H/BtBEGBeXd5sAFJxQdatDvTtbYBKnq1yggAmVEsizlPtp5h50tv7RQBkFHSp9
         uYezQnziasIAj0t0tBJKwZO8Yf4FuFQSJMh61svG/b5+LRcIsyBOSGovuHK/vqMSg/+H
         6/gw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=LCg4Gg9oRGRiXhW1Qi6ITGJ5RJILT70VyDqMKTSz9SQ=;
        b=WXrCMbK2Q9PV+Zha+D+3u+WS9x27gkx9Gg9MTLmaefm4X9mjeVFwMDlIgkkqHlxbLt
         Tc2fIIsxZxF7FFnto+KuQeYQ1BhWhYM+fjT6bXjTp6wu4Nt6H2DYSLmkq4cVdYjA/fNa
         +sRyNGQ2j4ot8N+xtVi9JZ/qOI09svnAaotyzAz2cRFSz0SJIVdexC/MPaxZviEDiO/G
         zFzfTCkNbAlWbDRMysEU6ksq2WXNhvf3K7P68ZOmIAuyuH9BwoM2SDqkuDhonx9IS/j+
         oQCYG8tCY147QUs7nCsgysc+OaxqllTjcFVHCg+0ZpK5KRvIh20WbUFJsgr+fsBfcrFp
         Me6w==
X-Gm-Message-State: AO0yUKV9f3jPc5/vh96PgKQh4l6U1LK5v0TB+5GjQXjxZcVqA6FwbicK
	GHiKOZYdHK4KrNaxnZtwyZA=
X-Google-Smtp-Source: AK7set/4N9QdVd89XN9E6moFs6dQvo5eC+F9zL4ErGp3MQDhtNP3XD5n55MAAmDk4iBqprnterNONA==
X-Received: by 2002:a05:600c:1c9c:b0:3df:d8c9:caa1 with SMTP id k28-20020a05600c1c9c00b003dfd8c9caa1mr927813wms.1.1677221121121;
        Thu, 23 Feb 2023 22:45:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b05:b0:3e2:165f:33d0 with SMTP id
 m5-20020a05600c3b0500b003e2165f33d0ls845192wms.2.-pod-control-gmail; Thu, 23
 Feb 2023 22:45:19 -0800 (PST)
X-Received: by 2002:a05:600c:43c8:b0:3e2:1d1e:78d0 with SMTP id f8-20020a05600c43c800b003e21d1e78d0mr7979111wmn.22.1677221119863;
        Thu, 23 Feb 2023 22:45:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677221119; cv=none;
        d=google.com; s=arc-20160816;
        b=AEbx2VkIEeVSh8Iq5o0CzH7K8W8m3rfsIdm8wG9AiKGnN65Jo6RCYuFl2RoH3Md/YI
         IPIpQgM0sjVnEYYkW8KM+Ith13e7sKhJL+Xz5uXOn2nSMsKDBHtPare1Fj0RdTYZSC1Y
         kB/g+vNZL/Zdz75EaqZtg8C/syjTm0H6jCmH7Kz2PeyvG8bJilfpVnhjrW6rGMKMEPlD
         otN6T/aaVvtMHsLVOFwY52rzaus0LJlktq8gHRN4RlE9QexNfHRRHbdaBEeE+4aR4C2n
         cCPXgak6ytWP5AIJ1EwC4qvgPTdtLaiDxONn4s/QypSMng5Khv2MP+ufli2gS9+zpStM
         xLIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4p2N3znozSpEZbXtte2eMWOETBMxmUkJjVlowyV2+bc=;
        b=djMay+1YXuWPd5nKM3Hz+Sphu6cFmSFGwuxjC4UnSyn5Sd3lKtswHzl9IXeNBtAxcU
         GXMCywsAyBrITTEI6C4rGP4SWjzqQUnJM7ATvpWF+EptFmVfVDQuatsG6SdLeTryMwsf
         8A/DIiNlultJB5yOYUDcO6R0vmWgYry1GpJNtsWaBWttlxO6ELThuIWmlUpCR0szf+lJ
         C6q0wzZKqaYo+p6EjlvZ629U4tus9AmOrnYt7DeGT+GsO+e3DAtahxHxfEiK79MN5UL/
         g0kDtcqaHxt4K58d0Hf8vtftnPrdzekFN1N266sM1JioRwUZU9PxrEhl8YCGERMSqJg6
         /P5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=N39tkFtx;
       spf=pass (google.com: domain of pcc@google.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x431.google.com (mail-wr1-x431.google.com. [2a00:1450:4864:20::431])
        by gmr-mx.google.com with ESMTPS id p11-20020a05600c1d8b00b003e21fa67323si70568wms.0.2023.02.23.22.45.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Feb 2023 22:45:19 -0800 (PST)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2a00:1450:4864:20::431 as permitted sender) client-ip=2a00:1450:4864:20::431;
Received: by mail-wr1-x431.google.com with SMTP id l25so12457036wrb.3
        for <kasan-dev@googlegroups.com>; Thu, 23 Feb 2023 22:45:19 -0800 (PST)
X-Received: by 2002:a5d:544a:0:b0:2c5:3fcb:682b with SMTP id
 w10-20020a5d544a000000b002c53fcb682bmr946077wrv.2.1677221119373; Thu, 23 Feb
 2023 22:45:19 -0800 (PST)
MIME-Version: 1.0
References: <ebf96ea600050f00ed567e80505ae8f242633640.1666113393.git.andreyknvl@google.com>
 <CAMn1gO7Ve4-d6vP4jvASQsTZ2maHsMF6gKHL3RXSuD9N3tAOfQ@mail.gmail.com>
 <CANpmjNNvGL--j-20UxqX_WjeXGiAcjfDAQpfds+Orajz0ZeBsg@mail.gmail.com>
 <CAMn1gO6reT+MTmogLOrOVoNqzLH+fKmQ2JRAGy-tDOTLx-fpyw@mail.gmail.com>
 <CANpmjNN7Gf_aeX+Y6g0UBL-cmTGEF9zgE7hQ1VK8F+0Yeg5Rvg@mail.gmail.com> <20230215143306.2d563215@rorschach.local.home>
In-Reply-To: <20230215143306.2d563215@rorschach.local.home>
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 23 Feb 2023 22:45:07 -0800
Message-ID: <CAMn1gO4_+-0x4ibpcASy4bLeZ+7rsmjx=0AYKGVDUApUbanSrQ@mail.gmail.com>
Subject: Re: [PATCH v3 1/3] kasan: switch kunit tests to console tracepoints
To: Steven Rostedt <rostedt@goodmis.org>
Cc: Marco Elver <elver@google.com>, andrey.konovalov@linux.dev, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, linux-trace-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=N39tkFtx;       spf=pass
 (google.com: domain of pcc@google.com designates 2a00:1450:4864:20::431 as
 permitted sender) smtp.mailfrom=pcc@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

On Wed, Feb 15, 2023 at 11:33 AM Steven Rostedt <rostedt@goodmis.org> wrote:
>
> On Wed, 15 Feb 2023 09:57:40 +0100
> Marco Elver <elver@google.com> wrote:
>
> > Yes, you are right, and it's something I've wondered how to do better
> > as well. Let's try to consult tracing maintainers on what the right
> > approach is.
>
> I have to go and revisit the config options for CONFIG_FTRACE and
> CONFIG_TRACING, as they were added when this all started (back in
> 2008), and the naming was rather all misnomers back then.
>
> "ftrace" is really for just the function tracing, but CONFIG_FTRACE
> really should just be for the function tracing infrastructure, and
> perhaps not even include trace events :-/ But at the time it was
> created, it was for all the "tracers" (this was added before trace
> events).

It would be great to see this cleaned up. I found this aspect of how
tracing works rather confusing.

So do you think it makes sense for the KASAN tests to "select TRACING"
for now if the code depends on the trace event infrastructure?

Peter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMn1gO4_%2B-0x4ibpcASy4bLeZ%2B7rsmjx%3D0AYKGVDUApUbanSrQ%40mail.gmail.com.

Return-Path: <kasan-dev+bncBCCMH5WKTMGRBIW74OPAMGQEFBKCDOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id C8BC1682AAC
	for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 11:38:27 +0100 (CET)
Received: by mail-io1-xd3d.google.com with SMTP id k5-20020a6bf705000000b0070483a64c60sf8321448iog.18
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 02:38:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675161506; cv=pass;
        d=google.com; s=arc-20160816;
        b=pXCP+s9AuHI2nPAxXXT8bi1bJRaGzy5g8b4PFKX7XQ7cdHS17J9EvPjUeBkWbdPUYS
         k1trEiaEr0ZvugU3T8CbxAU0VWA1iu31SQYv9Bnfj+hBixoojeXuD9Dc9RgBvJkwO/bn
         0I4f0PgJKITqIp7qUSyu85zaPM71k378wzY516qqLd59Fy1HalNVgKfY6qA1uH/eBaCK
         PQSW+T1c9nen1yovc1JX/fdwXIbGpk441PzLWhtsBgK+kq4ag2ZzqdPZ5OHHX1MKQoll
         3r0dYId6CEbS163WBlNrOAMGvaxmQ0mH8UsSKn0TTqSOtbcGzl35KY+lhasTu7LUKbLH
         i7rQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1A6Isqurrf2uX929mWpEX8qWaRyz9oTuhoVgIeWZGy8=;
        b=UcaoFQJyeUvM8SmP+eyf3yl4bVZ7vosHld0Ug04IXBdLM8IOokFUosQNrHG35F5FWN
         3pJyaQsLgPW1uk9Se4Qdw/CoThowB6vFij4QqHOfXeIy+XaZRDy770iYdzoy/4XsAvHW
         s6RuxAgmeR1HECGZc6KFzmvIXDkH86LWdgTglFim+KGY+OgfadoaTM7Nhq7amGZgB0Ja
         PDQ0/xLP1J0DroqlA/0Wz7c9QeQvSvxcUFJ/3KVpuza2cCHI9Pb/myveVZOrz3k1TrLQ
         3VZQCWBA6RgWRoIVpHHzXDUQqTsh5PBKIb4un6HqFEf8163t07iY1TMQa7Mvx3AEHUj2
         gDRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=iPwvJeD3;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::92e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1A6Isqurrf2uX929mWpEX8qWaRyz9oTuhoVgIeWZGy8=;
        b=SwaEoCt4jog7Keo8f4ONC0oecqECNPZpF3o0q5Lm26t6u5s+TO5zf9Wa5/gfw3RGN6
         YDvz7tUEO3dnmg6HwGyExcRx/VXK/BRIBX/md6gb5hAAJ7EUBUToS3wMhxRJtSPfuLPv
         b96/4vwgxXytoXvtzH7/lVkC7N8yi88cQNz8JSvv56kjDpI08F54j0KTHjrJYFpAR5ku
         9MTYUPZCmoxx+BhCA559Z3/LpIylFLu4+IBaTfjN2e3G1cHgDWp1j1Ug9s8KIyiGG1qQ
         l7fb5kvUWgdSaAiMlIeDzRIst4+IVczVQdpfTlWlwcom4aiTSZn4ibkksoEUbPBpVa/s
         5J0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=1A6Isqurrf2uX929mWpEX8qWaRyz9oTuhoVgIeWZGy8=;
        b=7muKjBOA6jcr5ws0I+08jNvPlHdhYmbnftKnokAXzLCIa9xEVWcaWfTWwKNZTncmhe
         PPT+w5DKd9q4hudxM/CJ0MhfiFhBDX6LE2CD6uV2EEB6nTnccBE/14TO8v6ZQxondcJx
         kCDnRU+dXV+14ZTXCNkhqbHIsPIQvNu7szJc3Y/fyIRigqAqhcSeEBJOu5SjTg9L/Ft9
         KWn6KZC/C1kMf9IxP8Qls+yQ/M29sLLwmrGOJRyFg4bU2pi8ifGqc3NSPjNqVjnC8j28
         B93MqG/fwbP4uvrPRDXcWaetEZDQJ9okd4003IJYHhNLK419UvvzOm/4cvndcrmgFUZS
         VFgA==
X-Gm-Message-State: AFqh2kqSwzuJ+doWcDtfibawvVpR0jvKD7Dr69zbmZn9im1QzHpPFMM4
	2mOEGZoGVgKx1rY4oYi0lgA=
X-Google-Smtp-Source: AMrXdXtIyIftLi2AccgvAPZAKL7muwpmV4sAg9UuskLt4R/IAxIPR9Dz637fB1qgVJcpfa7vIYjkQQ==
X-Received: by 2002:a92:c8cb:0:b0:30f:3c6a:838a with SMTP id c11-20020a92c8cb000000b0030f3c6a838amr6796765ilq.29.1675161506690;
        Tue, 31 Jan 2023 02:38:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:bc42:0:b0:715:713c:d8e9 with SMTP id m63-20020a6bbc42000000b00715713cd8e9ls1658838iof.5.-pod-prod-gmail;
 Tue, 31 Jan 2023 02:38:26 -0800 (PST)
X-Received: by 2002:a05:6602:2245:b0:71c:cf2e:92ec with SMTP id o5-20020a056602224500b0071ccf2e92ecmr4047470ioo.0.1675161506245;
        Tue, 31 Jan 2023 02:38:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675161506; cv=none;
        d=google.com; s=arc-20160816;
        b=ExA86uehg00k3fvRUl77D6shQDFNEHTyDb15L7R00ya58k2PsV305UL1VNUURlPvob
         I5VtmjqOD7ri+ike8mymkRn9ICtD8IUFP7wG0AN+zjuo3v72QGt0z7VYmkGSkamVuYNT
         XUMllbHQF1TmSy6EaQ1dDXKLC4GcxRDp8l2ZDDxFslRmZsJRGHTbOksXJXtRIPoR2MB6
         ecRZ8KaZD7BVqZmx8b+yNVhACwy2PNehPlrm4HDH3Kt+tcyUBXcHTZuJ5eWFwJ4RJjbc
         EtJcXGsake8u+fK3btaqs/bSVHXUseEBBG4oA1U8Xj0k9XbVu5ZaBTUi2eNVha969Po9
         UT0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+FR83tVbeEjgy0Oli/8j0skm7nFq9FbEOCLhEuugDSs=;
        b=TiGn8n6JqwP5CX9VIFS5jRgi014ckxtcfn4/PEIs4bCMXKYhXGz7wuEmbPjWVC/rTF
         USo7UuzjNZqvCPBBK7obuGCwtm/Ip/bIi2kVqPJLB+gfoEUK1kuEFwqbFydUrUWlfw2p
         6iTX8xKNlQbs00azShnxtB4gJqp75hwjxzXcKrczm3ta64SQdUiJJ/AXEFIOAqwVEC5z
         sgvIBLLJMqyeCfb2sLyjQ4AP7bg9ljZBviahOaX/qJS8pE0Ln+B1ZgsRZzZSMAboOhAd
         01gVg9JxtOFTp/907Z6IPr2wuyGdJFoV/1+TIUGSu62YiJtcBx1aUngFA8P8s/eWmMCR
         JpnQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=iPwvJeD3;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::92e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x92e.google.com (mail-ua1-x92e.google.com. [2607:f8b0:4864:20::92e])
        by gmr-mx.google.com with ESMTPS id s14-20020a0566022bce00b0071a86c5e11dsi511247iov.0.2023.01.31.02.38.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 31 Jan 2023 02:38:26 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::92e as permitted sender) client-ip=2607:f8b0:4864:20::92e;
Received: by mail-ua1-x92e.google.com with SMTP id a40so2834717uad.12
        for <kasan-dev@googlegroups.com>; Tue, 31 Jan 2023 02:38:26 -0800 (PST)
X-Received: by 2002:ab0:31d0:0:b0:419:d115:2773 with SMTP id
 e16-20020ab031d0000000b00419d1152773mr6564727uan.29.1675161505619; Tue, 31
 Jan 2023 02:38:25 -0800 (PST)
MIME-Version: 1.0
References: <cover.1675111415.git.andreyknvl@google.com> <eb6f0a014b8d0bfa73a8bbd358c627dc66cf51b7.1675111415.git.andreyknvl@google.com>
In-Reply-To: <eb6f0a014b8d0bfa73a8bbd358c627dc66cf51b7.1675111415.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 31 Jan 2023 11:37:49 +0100
Message-ID: <CAG_fn=XP=RducNNBr8oT6P8u5gN3QCpTKyjMSyUbLPO2ovgEhA@mail.gmail.com>
Subject: Re: [PATCH 07/18] lib/stackdepot: lower the indentation in stack_depot_init
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=iPwvJeD3;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::92e as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Mon, Jan 30, 2023 at 9:50 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> stack_depot_init does most things inside an if check. Move them out and
> use a goto statement instead.
>
> No functional changes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DXP%3DRducNNBr8oT6P8u5gN3QCpTKyjMSyUbLPO2ovgEhA%40mail.gmail.com.

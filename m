Return-Path: <kasan-dev+bncBCCMH5WKTMGRB5GW26VAMGQEZELP6YA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id DA14A7EDE3F
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 11:14:13 +0100 (CET)
Received: by mail-yb1-xb37.google.com with SMTP id 3f1490d57ef6-d9b9aeb4962sf777659276.3
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 02:14:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700129652; cv=pass;
        d=google.com; s=arc-20160816;
        b=iQAY4q9OWXOltDup055xs3+a5X6kpILWWOEUO9x+eae4fxWcpsm3o8y4SaTQHeJ3WA
         dNNJ5YUMkLyjiw51FqMOnRftsTMuMtBYXO7U8fZLlasPGLjxLnb8B1SFoSnu+4lTXbWo
         f3N0m5y4LDPjPd7Vpx4r+p0B7RquQBZJ4QoqSt2Q0WfaOgzI1rew7TPqPqJq4wWTO2H7
         llSnmmXn8YFDO/nfltsRKEd/nAS5J5Jp8lzdWHKdbFb0MCLqJprQ+WRYTC9l7pshJaiw
         s9HkypBhHgqyLzkuwlDhD+0h/WPZzxcunIS6APJoleGoY6opSyx6010EdOLGpv+GDiTg
         8QyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=21fVaMBwazH0OWgTIdSKVg0Gh9lsS1X/J8Wg41yaOrY=;
        fh=YZa8vkdUz4pzRj6QFVU/SyYW+LsIH/Wz0o5e5dUhKFo=;
        b=S1hXhoe0X8Tr61F6UMqj4ci0eMma31LD6LEvgmN68zBpGK9c68nm56XZxV5Niwm6k/
         XUH8YIIlMr8PLDdpJLAn0IA0X4kEhmu5TWC0qKMk7kW0rzS4iz6e5gpEu/MiAr+NprwC
         KV+UwDq/RLEJz2bzwcjpIgN5QVx1n8Z5JuUexEbSPlsE8dqOfwOYrcg8xf8cNcaTbPqC
         bEwUiz4PW4gnkG2I4cQG+Uv+/U+rmZTbmPXdaqZ4ik8NE//lWPfSKtsd9t4ZysoZBCdT
         DxF2fttl5v09f6psc2FO88xtLirfAJ0iv1bZGuQxyoxSvg2shsYMfOdQJypLtlvl2tCt
         ZaKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TEB72jS9;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700129652; x=1700734452; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=21fVaMBwazH0OWgTIdSKVg0Gh9lsS1X/J8Wg41yaOrY=;
        b=bmC508FqyxyfXeb78qrGrqm1E3vRZK/FzykXXeoxfrxbrMecs3JgaaO4Ya0K6F9roT
         /q7wApEpKv84RqWyzW7h+OXiqGYwsKeW0FlWHevw4Ud+/TJJ0Zx7F/vY+9J8g9VSskv/
         Y9wYQicLei66h6vz+wB2FD9B99iGvTItslKbnpJPOkBprfjeYVrTAiJpzavzUSN9jH0W
         F5VOB9R6pN7+XUvvP5Djn7emen8rUtXHKKHQrHUd56R9/ajxSrTtk/Y6btX2O4ULImPs
         1mgY9ie3OiZqm9oiPZcg4JpoA2vbNLEVsHRyXRbMrMj9PkCBbtLXyf+y3ujKCe5dS5Ox
         DMJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700129652; x=1700734452;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=21fVaMBwazH0OWgTIdSKVg0Gh9lsS1X/J8Wg41yaOrY=;
        b=KBLBGTLEV1mLBNBBeo3qv+VK5l68ELplCQMxPuzNg3ZfaptGAA5xxR7N75HhajagV9
         EOaZghjDz/km4Bf7V2+yxnzECce2AR86PVhYsq2XL4jMp21QVX6wOF8+iXnEwXAs8ujW
         OEvFpxqkIySQP+qNcS8EzRz7JzKMc3VzcBN0T8TBrd2sU2gM1yKPkOR0c/g0KejNY+do
         DyV3zDvw/tiUWgXqmP0LMMnFxkmHaVH+g+Hd+0v0aLUBysAO4tVCAJboAqAHs6Sbkext
         Dgi9YMo9vQ1074uccAzH2bZxkcZYDVnzj5TPKz2pUO4SQzcuiovxNleT6Rrq7gOAwesc
         ph5A==
X-Gm-Message-State: AOJu0YxtX+bahs534KJ/p9E6Ump07hUTaE6athpPhao90dQKfI9DZ+Nd
	heghUn/xdKww9EVKrKRE95w=
X-Google-Smtp-Source: AGHT+IGmfjtoZh/hslrwuxSJlNz41JsswsD18X7OSok1PXI97quHYn8Z0E4YKVLUFJnFZrXte0jsQQ==
X-Received: by 2002:a25:728b:0:b0:d9a:3d70:db36 with SMTP id n133-20020a25728b000000b00d9a3d70db36mr15904123ybc.42.1700129652552;
        Thu, 16 Nov 2023 02:14:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:7758:0:b0:d7b:9b5:ba6e with SMTP id s85-20020a257758000000b00d7b09b5ba6els920593ybc.2.-pod-prod-02-us;
 Thu, 16 Nov 2023 02:14:11 -0800 (PST)
X-Received: by 2002:a25:6a88:0:b0:d9b:4b94:adf5 with SMTP id f130-20020a256a88000000b00d9b4b94adf5mr11763600ybc.14.1700129651644;
        Thu, 16 Nov 2023 02:14:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700129651; cv=none;
        d=google.com; s=arc-20160816;
        b=Qu3R5sGYYJg0dhziOFBrv4s4H5KwObqLBqs/qt4g4rn5IinHNQL94WdZBd07q9owbD
         /yVa5jdT2Ttm4pPXWRprpuwnalyZHiH6fgRcVfWhzBqMXxi1CKh22xQiqOfJ+uVtLTJR
         /E7bSSboQZXdWY/US7P41pM/OYdOo5kGNZZpffT57AB5GjFLmARF+Ul3UjIEGgJhlvHb
         9gV/nHtiQKlRYijIFPaz/rGSGKl4s9qqAfd1RFQxI9IPLyG04E45BcQVnyVBg4vFx+GM
         8g3tw382fg8MNkfPdwUWsovpBKzab5pdBNThfK8szC7MGvXL82d3ytbMCPCekYEFSapm
         Akng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=S5z27wFZQcKESSrI85AK8SZJIpmMB6uhj5fEtkmaII8=;
        fh=YZa8vkdUz4pzRj6QFVU/SyYW+LsIH/Wz0o5e5dUhKFo=;
        b=eR5kZDC/RjY2gAfI4jgyUFXJIw5vI8W85qLJ0Fu2FUM5XEVEthfvtxo4h2RBnHPWKm
         XM4lQ56cQK8REqKm2HiWbm8c5EtQu5SbjiPUbsYt8762wxfvUbQPEDeBxjCWSagjXS9t
         oP9HDUhFRnBTQfSGALepQ22KR5QvyUqxtJiEfjx53OXayIRvJeIVdmFPYbn/wSAF6e5i
         Ua7wVHuXR3aP+AW0OPjjD+zIduOfeAE7FhMxpwKSbEOM/YmUcTcxA60GPJHARr8QkyKO
         2ga6qyAHB/NldAO3VOkdF6T9XIyS6yBYcy/deWOFNjkb3HM81gwYJhV8fOHkpfvsnIBV
         ucvw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=TEB72jS9;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1129.google.com (mail-yw1-x1129.google.com. [2607:f8b0:4864:20::1129])
        by gmr-mx.google.com with ESMTPS id eh14-20020a056214186e00b0065afd3576a7si1002239qvb.3.2023.11.16.02.14.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Nov 2023 02:14:11 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1129 as permitted sender) client-ip=2607:f8b0:4864:20::1129;
Received: by mail-yw1-x1129.google.com with SMTP id 00721157ae682-5afabb23900so6795967b3.2
        for <kasan-dev@googlegroups.com>; Thu, 16 Nov 2023 02:14:11 -0800 (PST)
X-Received: by 2002:a81:47c3:0:b0:594:f864:8507 with SMTP id
 u186-20020a8147c3000000b00594f8648507mr15893002ywa.51.1700129651150; Thu, 16
 Nov 2023 02:14:11 -0800 (PST)
MIME-Version: 1.0
References: <20231115203401.2495875-1-iii@linux.ibm.com> <20231115203401.2495875-7-iii@linux.ibm.com>
In-Reply-To: <20231115203401.2495875-7-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Nov 2023 11:13:30 +0100
Message-ID: <CAG_fn=Viz99-GHX0rnKWo7Wdhw+BLHqNXY_AV0-pT6d1OiGw3A@mail.gmail.com>
Subject: Re: [PATCH 06/32] kmsan: Fix kmsan_copy_to_user() on arches with
 overlapping address spaces
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Marco Elver <elver@google.com>, Masami Hiramatsu <mhiramat@kernel.org>, 
	Pekka Enberg <penberg@kernel.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Christian Borntraeger <borntraeger@linux.ibm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=TEB72jS9;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1129
 as permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

On Wed, Nov 15, 2023 at 9:34=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.com=
> wrote:
>
> Comparing pointers with TASK_SIZE does not make sense when kernel and
> userspace overlap. Assume that we are handling user memory access in
> this case.
>
> Reported-by: Alexander Gordeev <agordeev@linux.ibm.com>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DViz99-GHX0rnKWo7Wdhw%2BBLHqNXY_AV0-pT6d1OiGw3A%40mail.gm=
ail.com.

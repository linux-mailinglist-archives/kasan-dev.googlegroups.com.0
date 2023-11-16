Return-Path: <kasan-dev+bncBCCMH5WKTMGRBQXM3CVAMGQENCFL7PY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id DFDCD7EE471
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 16:33:23 +0100 (CET)
Received: by mail-io1-xd40.google.com with SMTP id ca18e2360f4ac-7ad53e60549sf74155039f.2
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 07:33:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700148802; cv=pass;
        d=google.com; s=arc-20160816;
        b=e5l5eZbKd9TtILc8s8EdNKm69r3z57lrVwhf0RkG89mFNo6gWdkTqecH/HezK2XpCZ
         1DphH5hVpDvQTdZwgoXzvu6zHSRaL7TSayPeeRkDafjV9XiS4HVslTWi5ixdonrrJ3/O
         igXoFv+V5B0mVnoDuPvKnjwLX0wezzdlVq+f1bEjpObjbl8Z5EXgfXxvLG3BLtW0t0fB
         Mi7h3rY+rpoSGdMx3mbxqRdgytJpAxIUYskPp62+Du9CMJR6xdLm2Vt7PxjIft8eT267
         a1h3t2aidbvDusryAZwPCrFAtznhI/jDCNPtq1BtL9P9i5Gq4EDTF1rWSZvqqQTkQnv2
         DWRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QJK8AjwAKZIqzpOAdZlrY0WhqjU6f1TZRoI7N7Stqy8=;
        fh=YZa8vkdUz4pzRj6QFVU/SyYW+LsIH/Wz0o5e5dUhKFo=;
        b=WlGumjRbYmkCwzuK4q+a3aAXmjykK8TDcCPBGY9ZKX6NiuS7JN830bJYi6pTg/Y98U
         jNDmeC8AMECCHyUJ/Nhrm0n7xCXl0Pl5N60gHHM1W94ad2vFteJNdvPAFBZ+jVWJ55e5
         5mYJg6YfgygE7/TzRsbBpWvzRdiTscE4CFv3G2yqdXP0l9/RvoEfWP7kpz9r/VO1lZi/
         YKFU6NoX7oIZBPrhvZRUzVx6gTEFiajoGVqEVpyzt3uZaAq8vaDn75mjeE7Lg0q9ftci
         tvM6Fzl2xUYYzGjMOVTzqtSZfMcxloSlgvmLhE/aRvUN6cE+MNewc3TnJ2Oh8z7al5ug
         kkSw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="bQIc/aeF";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::336 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700148802; x=1700753602; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QJK8AjwAKZIqzpOAdZlrY0WhqjU6f1TZRoI7N7Stqy8=;
        b=Ygz5IYfNA0nSns6hU7Rc0kqjx+HRpi14aoD2dGZ7MHDdH9K5cR7ttDpEwUh44UViBJ
         oPNdBDyPw/mWfUrPE23YtHRHWXYaqYx8qv2MxoT/ylO0tVjVYkxE54IVCdpVgbI6YSwL
         NkJ7tqlUjYfcCbWOyXEOvu4JcvlkLUBfVFsBJYkeCUVL/UonHXFE8FRVUoQnmRo86VYW
         x3c3pBMAmGbT169X/LyjCxI66mLrjFY1KYueYehw7G9zGNkFF61Xt627FZ6D6QHI1dww
         MIEppmgmFf3kw6+F8jWms140ATFO6KDolkTB0XXAGX9wKe8EYjcQ4VY15w5S8MHBO5Qb
         OyJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700148802; x=1700753602;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=QJK8AjwAKZIqzpOAdZlrY0WhqjU6f1TZRoI7N7Stqy8=;
        b=np1nIFU8JTgO1UbEsg5TAIGT3kDzK8ZRAvCjd1lApLtIYs7uO2DY+lPg3A05sAMVYX
         gjc0F1IaOGYEIOwt5xRFWkAfDUMRrzTh9cPlb6wAyZmyC6sG+EYBDrDYAMJ1wYEX8ywe
         /nbSYJ5j+k5OuUK7jVrgxw9nEX+heV/GwW7empRvl63xC30JrNlfCv4jvIdRlJ8Nz/lm
         FAOGqY/P/R49sGxKeYsyCJWm0DsEpIRbXBL0SJgzviw6meLWiNQNPS43Q7agmIe/vjUN
         lUxWCv+Tw+Ty3QNHNWQEEcoFT5aEZEMaawxWv1Tq9iegnsWMMv5zDdkp36JX7JwKh1U/
         eavw==
X-Gm-Message-State: AOJu0Yz5WEzT9Z4JYrdwRJaM3d4i8+ZoMDQduD034tPqwjynxN6yEQfu
	qMSUrBECWrQLl40JxnhxmvA=
X-Google-Smtp-Source: AGHT+IHQr5ufFASnxXCRlusS1TIFESxRLY8GJ4lfBJm19cogVJrKqH1q3Kzq9/R+h9gf4ZbdN8mubg==
X-Received: by 2002:a05:6e02:19cb:b0:359:4d54:52f5 with SMTP id r11-20020a056e0219cb00b003594d5452f5mr25571879ill.0.1700148802372;
        Thu, 16 Nov 2023 07:33:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2182:b0:352:6621:64a9 with SMTP id
 j2-20020a056e02218200b00352662164a9ls553977ila.0.-pod-prod-01-us; Thu, 16 Nov
 2023 07:33:21 -0800 (PST)
X-Received: by 2002:a05:6e02:1c0b:b0:357:3d32:bf76 with SMTP id l11-20020a056e021c0b00b003573d32bf76mr21588904ilh.1.1700148801235;
        Thu, 16 Nov 2023 07:33:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700148801; cv=none;
        d=google.com; s=arc-20160816;
        b=a+Gp7D3ssFjoCnDRJ3tK1YiWSyWYeqztryA94vSHMXyjD9zHUdv2ZpnVjJ3nKBCMk4
         o0+GyXN+s4SKRSmHbrIBQdxrNKdzGNoiYqiQt9b7PG0AJhTE0lteR6j9UWelAc7C5wnF
         WiMvq0VB3sdlagXo+YBL4TDsoTGthb889HIL+Ze1M9ia1TwHxTs0mee0REtcI0AMyUm3
         yC1sf9/rJIcIYqiYyWp4Tm28t+3d5guJMg1Cfr3vQHgoIJkRJYPyDhFD2BrryQZSPxXP
         2eyFKgLhZqxCj0put2qYYsi0PKOBKisYiYehCO1ZmxUS27LWyPuKsI77HHyRo0pFQK/c
         +TQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=jigcuHsKegNHRurmm53lq9/67DRAvCMuAyvTeznimbI=;
        fh=YZa8vkdUz4pzRj6QFVU/SyYW+LsIH/Wz0o5e5dUhKFo=;
        b=QJ/O1eJCR75SB88XPkAg8HLtz/w6Gj3z2nLB6o+pQDYG29y/zuDGCwuJtBZx3ro39f
         E7UhTq/ZcWf77YqlCiHbAZmgJcLtMKKR0W3Kvq13DeIXRPzaGKeJ5qbS+etGagTllTIl
         AQekQNOeMWWKgGo7+d0VsxTEkoHn/i8KjzzUFH8YQlM8oAtOwciu4o1JEQXf9DXeZa3Q
         02GmL0z2ZFhls68qyVvjEhjukXcvlLkF2UwOV9W2OR0+U03DLOc9hggs71NI3ULx9zNV
         bUR+N9ButCz8gnP5zO0gIOyA2JK0+WaGBTjWzl3uHv2MBgY8awXUfEPUohYVY2mvRbeg
         aaOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="bQIc/aeF";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::336 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x336.google.com (mail-ot1-x336.google.com. [2607:f8b0:4864:20::336])
        by gmr-mx.google.com with ESMTPS id y22-20020a05663824d600b00457c45edaecsi1452970jat.5.2023.11.16.07.33.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Nov 2023 07:33:21 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::336 as permitted sender) client-ip=2607:f8b0:4864:20::336;
Received: by mail-ot1-x336.google.com with SMTP id 46e09a7af769-6ce2c5b2154so490358a34.3
        for <kasan-dev@googlegroups.com>; Thu, 16 Nov 2023 07:33:21 -0800 (PST)
X-Received: by 2002:a9d:4803:0:b0:6d4:733e:e3ec with SMTP id
 c3-20020a9d4803000000b006d4733ee3ecmr9485460otf.37.1700148800736; Thu, 16 Nov
 2023 07:33:20 -0800 (PST)
MIME-Version: 1.0
References: <20231115203401.2495875-1-iii@linux.ibm.com> <20231115203401.2495875-29-iii@linux.ibm.com>
In-Reply-To: <20231115203401.2495875-29-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Nov 2023 16:32:39 +0100
Message-ID: <CAG_fn=W2t61Y-ZTgmnu78mpcpPRCzB-hk9YZoD8RXXdaKHV0MQ@mail.gmail.com>
Subject: Re: [PATCH 28/32] s390/traps: Unpoison the kernel_stack_overflow()'s pt_regs
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
 header.i=@google.com header.s=20230601 header.b="bQIc/aeF";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::336 as
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

On Wed, Nov 15, 2023 at 9:35=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.com=
> wrote:
>
> This is normally done by the generic entry code, but the
> kernel_stack_overflow() flow bypasses it.
>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
>  arch/s390/kernel/traps.c | 2 ++
>  1 file changed, 2 insertions(+)
>
> diff --git a/arch/s390/kernel/traps.c b/arch/s390/kernel/traps.c
> index 1d2aa448d103..dd7362806dbb 100644
> --- a/arch/s390/kernel/traps.c
> +++ b/arch/s390/kernel/traps.c
> @@ -27,6 +27,7 @@
>  #include <linux/uaccess.h>
>  #include <linux/cpu.h>
>  #include <linux/entry-common.h>
> +#include <linux/kmsan.h>
>  #include <asm/asm-extable.h>
>  #include <asm/fpu/api.h>
>  #include <asm/vtime.h>
> @@ -260,6 +261,7 @@ static void monitor_event_exception(struct pt_regs *r=
egs)
>
>  void kernel_stack_overflow(struct pt_regs *regs)
>  {
> +       kmsan_unpoison_entry_regs(regs);

I suggest adding a comment here.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DW2t61Y-ZTgmnu78mpcpPRCzB-hk9YZoD8RXXdaKHV0MQ%40mail.gmai=
l.com.

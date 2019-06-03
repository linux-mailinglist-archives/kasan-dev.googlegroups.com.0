Return-Path: <kasan-dev+bncBCMIZB7QWENRBHPX2PTQKGQEAULSMBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3e.google.com (mail-yw1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 877BB32E00
	for <lists+kasan-dev@lfdr.de>; Mon,  3 Jun 2019 12:51:10 +0200 (CEST)
Received: by mail-yw1-xc3e.google.com with SMTP id l184sf12536584ywe.10
        for <lists+kasan-dev@lfdr.de>; Mon, 03 Jun 2019 03:51:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559559069; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z9aJCoKlZ+/L3FAKFn42dc8KEuuTG4wdA3kOkUiv0k1i+hhH9arOEaBvg636Q7iI5z
         sFVV/7WS2AVUot4mK9C3JhPyQUaQGvQBSAUZ0g2l/ZPgH8AIHx75zFfc27tu52F2ZEYg
         INcnkyKUFgnPkk4/bdu7yIHiLGBYYtw/FTxUs3IeU2VhhAaZGA+Ea0GEvo9n9DOoP9m8
         fywL1SY185uIkrCmNVC+Nuw2BwC4EEApoASbO0mH1VpD1HPRk04ctlLiwYZrIQUYUUEa
         iEXh62PACHUssjODtKGETzDrG2fv+IeG1xP+JFFEyveAMK8eYwcNWAAwKLViTTa738bC
         dbpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=cRSSIOiulQxYNhFnzrO65GFSq9eIz/FkwBwhPFSCUsI=;
        b=Wp8fmsh42YjK7fpEnyn7fzKxDZMq7Bk6sQ99vPv/FPEcB5Ol1BY41+GX9bWdi0Rado
         5PoKCkPkGf1fjeS3gERGuS6DjxNKSdzVWNGQscx6h7RobGG5hNUBV1Rlyh2jfudPaR6U
         oLFt2RqkZt9cZ9Co64s/ONN3U0IGCGACigXk1m1ff5tlbmD4gacaJaq0QwBwo4iwGeSu
         QAzk1sNl1OhOpzJW53OZT/LH3JevF3eGacd8pEJoW5zAQqSmtQ6uBx/aolP/cBBf0ok1
         vqO2u6SvHPVOey5Yuq9nNvl6HLjBDqVuPT7gNgTmfSPYasvhMGM2bpIuzQyb+MmTYeqY
         HASg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ui2HFJbr;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::142 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cRSSIOiulQxYNhFnzrO65GFSq9eIz/FkwBwhPFSCUsI=;
        b=RYcbnCiqIeYzSx//HZKsXHp6+wzbkoT8bOWVX1R5tEXmdW6rJ7bsK2TkbqjVC6/zXq
         DaYIPZUnze5gpRVxtHztbA8nDlVZbWk4V8kTlUaQBvtjwSDVZ9Sdndqo3IDlT96qB//C
         +StW+kOqLvyU4Ue04ywpIJVm9i9QYRQNlznapQvhWgI8siU9Ap6LBepd/WnCfP+UjJWs
         cdFLqqC1pF2YwFC0x0HxAKQPm/GJZdebWw+GfEuVh9u5CpsjUt4W6Wm+sW03YOV645sT
         ilbfhqD6f8aFkanYHl8JBowSmbbi4Lq4bgu6VZETYosoqjRs4RC2fm8+JlQ4Qza4KDay
         nasA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cRSSIOiulQxYNhFnzrO65GFSq9eIz/FkwBwhPFSCUsI=;
        b=Xiy3QxJxJiMn+5gQ8P6e06HlO5WCGExvn8RuoQIXnef19cuDPotg1dxhQlOXvypikJ
         canCzTJNq1GJjy5x0J7xmGPg+RR9GZ/LW0lTqkCtECccxKCTyuRPEcZKuKNDLVIl9L4f
         D+ccwhXcgUV85echI4jUywH+/wGWKk1r/eQozJkXfl0rA+deG/JN/6ID0BfrYPm7pG1t
         umJeUTU7CA8ZeTNDCFzBzX7gh3LBsuugNUzbKQorxPu4DXa8sPGRwQWQ+ZWYvfJ0QlNT
         Nm5kTDcyCXWyvlIyl/yuhwyQyGT6AmCAtDmov607UBGwTFJAnwdZrSJjoGXQS280/sFQ
         eW4A==
X-Gm-Message-State: APjAAAU2u72Wfkq1ZwWYJGms27s3XUSHvuwENAIi5VdfkGajEWv3Gi5V
	o7L06WYE6/Sl0RR+7cLXOKE=
X-Google-Smtp-Source: APXvYqyd4cdI2BTUqbG8DurZh3tF0W3twpQfY26bDX/KU+h2nVZXIVN3IpyF06R3V48nnThgORkJmQ==
X-Received: by 2002:a0d:e841:: with SMTP id r62mr898088ywe.497.1559559069339;
        Mon, 03 Jun 2019 03:51:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:3447:: with SMTP id b68ls1456956yba.5.gmail; Mon, 03 Jun
 2019 03:51:09 -0700 (PDT)
X-Received: by 2002:a25:b441:: with SMTP id c1mr8614775ybg.476.1559559069036;
        Mon, 03 Jun 2019 03:51:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559559069; cv=none;
        d=google.com; s=arc-20160816;
        b=pqEyQGqewtQmazSJm0j7TwPrrAIncC1cXsJd9SpRod0EdOU3vECsXjvV8SZbiAY2ez
         h1CtkGdAPqSNnakbGcsDUWKzQ0fUTq/n2i+o7BH01vuznX2VzASAeSDyMu6rm9g1Zuyu
         DjbIge58iMVZBVxm9z4+rHca4lc8MA1Z2ftdtSppTEhGDeWJ6pFMTUD0F1Rxri5Nd/AR
         kJYAAj1rdspr2OHfC2PxNkQKclzmf6PAFJMyQw5+vTzVlgcVIAUWCGN0lW148hCi0E3J
         LpQsCVuGAzNN3XSjVfIMPC9xsfd3GUaZCD/Cgcuj06Ea066GoJAbA/slV/dCYKfk/p/X
         sLjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JVlFqe9K3dpzMXBqO3onEIwgqdoMrC9jSiKlsTsm+KA=;
        b=pFNIXlaSZIMfv0GFySVeHxp8+q/KDFzb3UUbTTMpQfcymmo+Ut6HbCUt3pIiVjHhjY
         6Smkgla9tzaWXWpK1ZEtebtZtZMCA49e37HSkFQI9dYUUvGGc6WkSvowu1DReRc0yU2F
         i/vg8/wgjl9ZI0zd/AC0kh3KryGDeaispvI+IYJmhT0mNLGPE3Jg8PGuKMSH84ibdqRV
         Day7TTLjQbxzAMpLZpyoCoXbxzbHkhj7xAQH3C4x/5Kqj3lNiYYzSi3jPWYXr5ZpQ5wz
         Ty1r+vTVWQ93VERVo18MqfbfkHLInIw94k+bzuRZNYrsoX9bWk2O8/Y2oNM53ZQgKUUO
         DxcA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ui2HFJbr;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::142 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-it1-x142.google.com (mail-it1-x142.google.com. [2607:f8b0:4864:20::142])
        by gmr-mx.google.com with ESMTPS id d5si226772ywh.4.2019.06.03.03.51.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 03 Jun 2019 03:51:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::142 as permitted sender) client-ip=2607:f8b0:4864:20::142;
Received: by mail-it1-x142.google.com with SMTP id m187so793085ite.3
        for <kasan-dev@googlegroups.com>; Mon, 03 Jun 2019 03:51:09 -0700 (PDT)
X-Received: by 2002:a02:22c6:: with SMTP id o189mr3896549jao.35.1559559068416;
 Mon, 03 Jun 2019 03:51:08 -0700 (PDT)
MIME-Version: 1.0
References: <20190603091148.24898-1-anders.roxell@linaro.org>
In-Reply-To: <20190603091148.24898-1-anders.roxell@linaro.org>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 3 Jun 2019 12:50:56 +0200
Message-ID: <CACT4Y+Yes1Fxk24qemvB6b7NWzSD24ciqZsm0UN61jph46EdOQ@mail.gmail.com>
Subject: Re: [PATCH] mm: kasan: mark file report so ftrace doesn't trace it
To: Anders Roxell <anders.roxell@linaro.org>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ui2HFJbr;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::142
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

On Mon, Jun 3, 2019 at 11:11 AM Anders Roxell <anders.roxell@linaro.org> wrote:
>
> __kasan_report() triggers ftrace and the preempt_count() in ftrace
> causes a call to __asan_load4(), breaking the circular dependency by
> making report as no trace for ftrace.
>
> Signed-off-by: Anders Roxell <anders.roxell@linaro.org>
> ---
>  mm/kasan/Makefile | 3 +++
>  1 file changed, 3 insertions(+)
>
> diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
> index 08b43de2383b..2b2da731483c 100644
> --- a/mm/kasan/Makefile
> +++ b/mm/kasan/Makefile
> @@ -3,12 +3,14 @@ KASAN_SANITIZE := n
>  UBSAN_SANITIZE_common.o := n
>  UBSAN_SANITIZE_generic.o := n
>  UBSAN_SANITIZE_generic_report.o := n
> +UBSAN_SANITIZE_report.o := n
>  UBSAN_SANITIZE_tags.o := n
>  KCOV_INSTRUMENT := n
>
>  CFLAGS_REMOVE_common.o = $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_generic.o = $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_generic_report.o = $(CC_FLAGS_FTRACE)
> +CFLAGS_REMOVE_report.o = $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_tags.o = $(CC_FLAGS_FTRACE)
>
>  # Function splitter causes unnecessary splits in __asan_load1/__asan_store1
> @@ -17,6 +19,7 @@ CFLAGS_REMOVE_tags.o = $(CC_FLAGS_FTRACE)
>  CFLAGS_common.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
>  CFLAGS_generic.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
>  CFLAGS_generic_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
> +CFLAGS_report.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
>  CFLAGS_tags.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
>
>  obj-$(CONFIG_KASAN) := common.o init.o report.o


Acked-by: Dmitry Vyukov <dvyukov@google.com>

Is it needed in all section? Or you just followed the pattern?
Different flag changes were initially done on very specific files for
specific reasons. E.g. -fno-conserve-stack is only for performance
reasons, so report* should not be there. But I see Peter already added
generic_report.o there. Perhaps we need to give up on selective
per-file changes, because this causes constant flow of new bugs in the
absence of testing and just do something like:

KASAN_SANITIZE := n
KCOV_INSTRUMENT := n
UBSAN_SANITIZE := n
CFLAGS_REMOVE = $(CC_FLAGS_FTRACE)
CFLAGS := $(call cc-option, -fno-conserve-stack -fno-stack-protector)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYes1Fxk24qemvB6b7NWzSD24ciqZsm0UN61jph46EdOQ%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.

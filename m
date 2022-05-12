Return-Path: <kasan-dev+bncBCA2BG6MWAHBBSV26WJQMGQESZBPDCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id BEF7552559B
	for <lists+kasan-dev@lfdr.de>; Thu, 12 May 2022 21:17:31 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id e3-20020a2e9303000000b00249765c005csf1880934ljh.17
        for <lists+kasan-dev@lfdr.de>; Thu, 12 May 2022 12:17:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652383051; cv=pass;
        d=google.com; s=arc-20160816;
        b=xaDA1FJXE4fuGwtEHBWh5ofzGBZE6OHPPE70PXKeoQDjAIJ/hzDX90HhH8rbwkKgV9
         wiipIjI76wMAOao2L3bgvuh7ulJl9/AQtBwRPW/hTkJ0OkLyXciMd6vQNhCoL+0UcMb4
         VY7mX8ED0AeD95o8uWeXC690yv5ubtWp3BNraA57Z71etFAIUGywn3euRhu4wd8MIPCj
         WJbduXj9BFQxNAM7uHd44dmgxVsm1jgiC6/3mUjkm3Yl3X08KgyHkmn6laWoPznVOMXY
         4OW7qiyieKAfLH38Mv0uyZ4raWYdtJAzK/rt8Dc6FzEbKXwTDYevz5QI7fE1D0l9Tpv6
         NFyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=WqZhtzY3czjgLJN+m1f7QACBDBwFrybFtyJgEOm+wGo=;
        b=GdCYPEoQyrVJ8cMaAU17SeIYj8xLLrNUCdRYNOhrIbsc58IDbvZbiLs5EjXg9RdKPP
         PVJmJTSdHmR5+Fr4unzO7Wm052cvV2oIJ8V6rAb+gFdRN/UTFhGCx4EGv1AuUIDbUa/7
         lw1kkBH8Yy0ZqXkAVlkbJ6TZ5NzuY2SP0zUPMs9YNe9nmjMfx2xAjoxTqnY62ADwZk9Z
         MmaSktnAdaMDqnyZKWvk5O6idsf53zaXPOZqag7OZfJqfsvbKceRgYwAYYXS8w8HWwCT
         gGMMysnsH2CyALQEnRr5pWBnu7tME4gmVDs0S2HlOMXJArl1nRQdnoFf/fCI761rejeU
         GJIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LKho6slM;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::633 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WqZhtzY3czjgLJN+m1f7QACBDBwFrybFtyJgEOm+wGo=;
        b=fAX1MLnN7mnPls14u9gX6Lrdyb3KXVFoGDnbmlNrA4oMjDQu1JiA/hkPBtrduE3DgA
         YzrF82f7fB7S0xwjtfP4obTJxy29YFLxowGBy1EKsfjM6LKr1n8LkykIFfj54Ve5OYub
         Am5JquM8L1wlCU49d01zsBGAv/JejqY+RPP/XZ7s616e1L2mMRfqYgwZA+Kzxf+TO2da
         pTXfHUNurJUcbYzBSHizRLcSqtOZx93U07q3At/qbT03WLytW7YPpgZ+1+EL2O3rmpog
         MJyWIUQ9uMX9sDIQfVfuQI1txdrZBZBtLbddbFddEiqgG6VJdinVM4ug8u1eDODl0iWv
         0p4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WqZhtzY3czjgLJN+m1f7QACBDBwFrybFtyJgEOm+wGo=;
        b=lUMHvvg6oFdlXNQaqQDacShrqK5vUwopYldTZqt9qAZIxdD0Pk7V0XMtdsr2DeuBxD
         eJU15tjJn/WThueNUO80vrMmcEH9x0RzhjDQd60R6oOortHUX6Eb/3M/XgSkz6F/TUCt
         lzKbb/zMFnCKIU5XgyglIIExSy9TbvXx19E23QKD/FGXy/85BSy61uk3GcqNrYlIqU3S
         Nr/wNlfLsbB8B3tcQvYH11vgc9fVK8rvn/t7537Mi7hisYUwk8UQ0dhRXZab3zY19n+g
         WbN9TjnzDe0h8CPUbFtGMXYMZdtKxZFb7usPnUghwwGdQd5jiJpjfOb7LMlquwyjii/7
         1tow==
X-Gm-Message-State: AOAM530/1HncyKNnQPY7mZDIFLfSMzCOJnKUXFferujF6NrhIZ8VyT8X
	GTAndjqGomgCGWSCk7YKPEM=
X-Google-Smtp-Source: ABdhPJx4JMYz5iFxRYeGNyEmOJWS7ZQL5gpP2DQ9pvFKHLK8BsKCbov0wmA6kazCHiTptOVbNU7nIw==
X-Received: by 2002:a2e:a585:0:b0:24f:528f:3621 with SMTP id m5-20020a2ea585000000b0024f528f3621mr924137ljp.416.1652383051215;
        Thu, 12 May 2022 12:17:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b1c:b0:472:38f0:bc75 with SMTP id
 w28-20020a0565120b1c00b0047238f0bc75ls2879774lfu.0.gmail; Thu, 12 May 2022
 12:17:30 -0700 (PDT)
X-Received: by 2002:a05:6512:b1e:b0:44a:9b62:3201 with SMTP id w30-20020a0565120b1e00b0044a9b623201mr932263lfu.42.1652383050132;
        Thu, 12 May 2022 12:17:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652383050; cv=none;
        d=google.com; s=arc-20160816;
        b=dWSfd1efbK4aYopyiaReMGsSQspMnYkE+/V93BeOPZopV4BQo21X6YfvRTiBWS4QLa
         w4kvYFYHvj7yI6SU+SpOavAtWKYvZB4xjdVLv1A1j6tSXhNYQTuifNqkk1CXCWEtGvUd
         rY/pNOVk3cjqv3T+dJsg5aqeOsn+dJuwxl0BIrzICJ+4pOZ3Rh92f1zBkrZx6MeZYkwk
         kWQ4YigJck411UjHA/c3yTswpvjUt059vvZxiQ/cL3YSKINLjazcFphJUv2dnuRvqUKu
         c6ybd0GDLmf7Mm6ZaiYQdMIY9xmzaHnooF4HL6/7u2YLh8OD7TZF8WQT256zpfkuM2Tw
         lWXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CWa+zByd3DqEl7xqKDtnBELPWtqlzD2Sn/Omv7A9MU8=;
        b=R0mXZaU7O7Y7fxRCX1tThkUhdVmFkZ+biewzAkU55+jUES8EGj6kyWMTeaDA6khBxF
         7rzKBaabTlTcGOryhSnaxWy14bOKxbX9dXMARydGNb81ezuRjsWHarwZKDyZlW9/7Lsb
         9Z/FQJ/vGctiWUU9DLMl5cqG5qxmj3FVWYUc0DT0m2YOs6dTpxE9rpPMS7yECsIMTsPt
         nZJI0YjV2BaIEmYFnb2Ot9MQXX60bhJLP+bvaMY1SD32rxXt0J78b9GEJnS0M4E+Y1bj
         NzaE36jgTh/m4hGeXDZf3VRoP8r6dP2rDUfgdyCm24IUpL+hPU/oGKqHpZyB2UotObYW
         prrA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LKho6slM;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::633 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x633.google.com (mail-ej1-x633.google.com. [2a00:1450:4864:20::633])
        by gmr-mx.google.com with ESMTPS id bp22-20020a056512159600b004723ec9fc4asi14508lfb.0.2022.05.12.12.17.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 May 2022 12:17:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::633 as permitted sender) client-ip=2a00:1450:4864:20::633;
Received: by mail-ej1-x633.google.com with SMTP id l18so12104741ejc.7
        for <kasan-dev@googlegroups.com>; Thu, 12 May 2022 12:17:30 -0700 (PDT)
X-Received: by 2002:a17:907:8a14:b0:6f4:4365:dc07 with SMTP id
 sc20-20020a1709078a1400b006f44365dc07mr1157244ejc.693.1652383049625; Thu, 12
 May 2022 12:17:29 -0700 (PDT)
MIME-Version: 1.0
References: <20220504070941.2798233-1-elver@google.com>
In-Reply-To: <20220504070941.2798233-1-elver@google.com>
From: "'Brendan Higgins' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 May 2022 15:17:17 -0400
Message-ID: <CAFd5g44MRx=bmu5kuFBKNW_KEYHLjsoVu93_hnrEkG8d3KDojg@mail.gmail.com>
Subject: Re: [PATCH -kselftest/kunit] kcsan: test: use new suite_{init,exit} support
To: Marco Elver <elver@google.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Shuah Khan <skhan@linuxfoundation.org>, Daniel Latypov <dlatypov@google.com>, 
	David Gow <davidgow@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: brendanhiggins@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=LKho6slM;       spf=pass
 (google.com: domain of brendanhiggins@google.com designates
 2a00:1450:4864:20::633 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Brendan Higgins <brendanhiggins@google.com>
Reply-To: Brendan Higgins <brendanhiggins@google.com>
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

On Wed, May 4, 2022 at 3:09 AM Marco Elver <elver@google.com> wrote:
>
> Use the newly added suite_{init,exit} support for suite-wide init and
> cleanup. This avoids the unsupported method by which the test used to do
> suite-wide init and cleanup (avoiding issues such as missing TAP
> headers, and possible future conflicts).
>
> Signed-off-by: Marco Elver <elver@google.com>

Acked-by: Brendan Higgins <brendanhiggins@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFd5g44MRx%3Dbmu5kuFBKNW_KEYHLjsoVu93_hnrEkG8d3KDojg%40mail.gmail.com.

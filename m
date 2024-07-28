Return-Path: <kasan-dev+bncBCT4XGV33UIBBP7LTK2QMGQEXS7LXAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id CAAFA93E99D
	for <lists+kasan-dev@lfdr.de>; Sun, 28 Jul 2024 23:18:56 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id ca18e2360f4ac-81fa12a11b7sf145637239f.1
        for <lists+kasan-dev@lfdr.de>; Sun, 28 Jul 2024 14:18:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722201535; cv=pass;
        d=google.com; s=arc-20160816;
        b=EGjOVsGWUHAUODtb6XOjGym0YrexoGI8mKk6TtLAcvgd4b6GQX3K7A9E5o2BoUk2tM
         +LXAsMIIV/X8bR7Sl768Y+StYb0h5U7XPWDYUrFDGoF6iPoEk4bTMFDLPHEN5MTI7FIO
         73Hl3xAoK6qWKHYQMZZCUfO2Yg/UntrZjvG3vBNBsBmSphDLSS9r0MKIeqiv8mpdyEZi
         Yvmn4KBLozqJuNHP+tfC84FKgdmUlod9G3m8+Bo7bQiReIybKEFMIP9ZPkkjntTmAZmG
         SKho/pxHlQG8pyeE3CdrZCh6ezETmBUMoN4qI2vcr5yJOmCvUC7QKbIS9UKL2ueAejDV
         byOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=Z8nJg/K/I0wQpATsQWwWjR2JiGxtGGWy54G884zyE9w=;
        fh=48CmImneiZG8X3vklkhljiQHX1/eOe2JUW7IiNQkaE4=;
        b=JQSiQOfHYLapGklniRZkitDvkxGyrmUIZyhCW2SwFrjZRTlPMVkYycCT9c4W429ROc
         7z+nwuhmhbAN0NEt9n2+YxPmSXkjWhWGlFvmPe6+c3ZGuroyQr8/c7ecQXAdV8VTEO1C
         PftICLaXAoYqblezPpDHzMCeVdZZYlA7KEmLXk6zqI/e35G9qrwek54Kp5AcJ4qA87QI
         SXKZrQAnFVGWagcgipmkQP0mJjNMQh7fdAo+74QYB1FARSloEJa64hfPGR0bv7lbM+Ja
         N+kEjDqHum1SxBPvNfTqz13bt6MKYFNLmVKcdc+uHOC/bnBEKhLzZHixzNLU2ByxPbmn
         bCBw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=LHAyydsJ;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722201535; x=1722806335; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Z8nJg/K/I0wQpATsQWwWjR2JiGxtGGWy54G884zyE9w=;
        b=hCWxDMvC9jIfR7c9u6ycOV95ZXAWfz4P3e8ajwySfSCk06UzI8M67IHSL4YRkBEpBo
         At3my6iyJLhOWw8CNK8Q84u3aQGUPPi1ipzIJKSu0zeL9LA9l25JQMujoWvFyiNZGj27
         Ju5XGknJQNmG37MOWvA4JBe6jef4vr1WIBRdx0ksKjC16HRp5d8fzbmPZUdFZPUuNPKv
         zx5KO6xUadJrwrlvyAasEfMGDFEbnDDGucFpKrIT77kHjMdxujbWYo0CJn97TEdaSTpS
         Tvgbr3+JnQYEa4+Xpnf61MZMfd13lpGUKI3cGXcx+dQhjNoB0Nol+RhWJUMH8KdDJd1v
         SyNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722201535; x=1722806335;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Z8nJg/K/I0wQpATsQWwWjR2JiGxtGGWy54G884zyE9w=;
        b=s5G7+c/imjtK3KK+R6HQUb01WM1WCU+V6nul10yRmbg+/a+0PQ67MBv3fkR8xYgECV
         kNP3QXmL9Iuy5jeeQPnI3VFfh8MHb+6Prr1xjCZ5ATtdC0aPNB1FFYl9SE9ypOc5aUqE
         Xxo5OVb0ptPtZcngsn0uxtm4hkFWm18rAJkUVI3RmDS7/H6/tFKN/NrhHlB/vT6Ne+t5
         9ksKSAoUdvm+I/UacOCZmyXj+iQ7Qu/OUSScfciJhN5FPEey1OdiDOAFccuf8/wVSfGs
         G77vrQnKD4CjMbVwb7kdVVYO0AWtdVveCg/CwQZ3IsVpH/sZQsoqSP1lP1Qj4V6zOQE2
         oc/w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWa8WccOfn7M39K40w+aM084ojKYU0AHqrMwT/erM0EZP/RbCwI5+gwrlItf+96KwfrWVbi0nvWtBmdDJKJOVaIDLWz0GrdMg==
X-Gm-Message-State: AOJu0YwrbzMrP0mtKwYOTlS47EwhUUQ+jShpQy7bdtD+iupGcsZkD2Dg
	X2GjtfvdNc19qWbWJbsMCyKQq5BD7eJfYvAceiLI4AXxi2o3fCAs
X-Google-Smtp-Source: AGHT+IH8vTscdLi8C99yh6raR9KqGX/ncVuQZ8/v1BVEFKyZcI2HmDfD4+AUth+3DZld4HuglQK3HA==
X-Received: by 2002:a05:6e02:216e:b0:397:70e7:143b with SMTP id e9e14a558f8ab-39aec2eae11mr81772405ab.14.1722201535382;
        Sun, 28 Jul 2024 14:18:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:dc4b:0:b0:39a:f263:546d with SMTP id e9e14a558f8ab-39af2635942ls6850695ab.2.-pod-prod-01-us;
 Sun, 28 Jul 2024 14:18:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVBso4jYZEYH+5olDdrabavqwV/AJO01DCA+orMeKlTuZGbmeFkgsiHtORzxp4l/qznCgm+bIp1oGE20win29cyK8DNMJ4KhL2xUg==
X-Received: by 2002:a05:6602:15c9:b0:807:aebc:3bdd with SMTP id ca18e2360f4ac-81f95a4f653mr718749839f.5.1722201534561;
        Sun, 28 Jul 2024 14:18:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722201534; cv=none;
        d=google.com; s=arc-20160816;
        b=HUh14VA+lm+HYg8MnC29q5TCkcJkfkXnuWWhxMqcj21EVe9qAVRQHtUfvk0oq20ubl
         yGguqdTWoSMsvDs+oLcgkmCu/j2RcTKiCPX2m9YVf+qHNwv+wa/gQoeb9Lok29yDVL2X
         ZVlZI6NwFkVANiEHs+5yRohwtf3/agsRHIciNTe8MmM3ChO/eLq6wJgid5ppeQV77Vlt
         QXuO60cCrjszYlicEJA7bnqDeMukgUWOqHlNg86kTSLMEnUaXAPlo/8qWoa/RL8vNao0
         0uUI4RUbvsK/qu8nv04u2uvNr7ELXvuyP5xFz6QOPdSvuLngBhLclPRpeq5K6ByEcMwp
         Za3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=p+wn079PYg7GE4Z2FMCZuTF8ldh4mxPK9a38/BKbOd4=;
        fh=icFmRCT9AmRrjURcDyIYT4LCOSxTO9k/S0Xg50cB4oo=;
        b=wtI5HG59S3dND8Fxa8/kb8FfB9lfHvDTIfwyZBjEuo9GBGvy+5gsdmsbw5UVV96xYX
         Pbe279ahD37unKqGhst3M+AtLXn2V0kqxmAY1Z6D1L6/Sc1irSugxvA7lYj4SVWGyaM2
         RGqu2WOXxOqW90U2sZum7SIvpUzppVSv18N4xoDYQV5vE2vVJn2MbApt8YfYOpJ9zku3
         RdYuncR+YwARBH+PABdf5KHnr7vVjTehvwrabxuOSXkfhicmk0DtfGm/1HPcbruHDPD+
         NyG+FyCEe9Z6OEEUWVxWwHajptafdHpvLd2nFal6ppH+Mry4i2qS9L5+CJIQkJC8RU/x
         me2Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=LHAyydsJ;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-7a9f650778dsi464653a12.2.2024.07.28.14.18.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 28 Jul 2024 14:18:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id B963BCE098C;
	Sun, 28 Jul 2024 21:18:52 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A9CF4C4AF0A;
	Sun, 28 Jul 2024 21:18:51 +0000 (UTC)
Date: Sun, 28 Jul 2024 14:18:51 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Adrian Huang <adrianhuang0701@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
 <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
 <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Uladzislau Rezki <urezki@gmail.com>, Christoph Hellwig <hch@infradead.org>,
 Baoquan He <bhe@redhat.com>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, Adrian Huang
 <ahuang12@lenovo.com>, Jiwei Sun <sunjw10@lenovo.com>
Subject: Re: [PATCH 1/1] mm/vmalloc: Combine all TLB flush operations of
 KASAN shadow virtual address into one operation
Message-Id: <20240728141851.aece5581f6e13fb6d6280bc4@linux-foundation.org>
In-Reply-To: <20240726165246.31326-1-ahuang12@lenovo.com>
References: <20240726165246.31326-1-ahuang12@lenovo.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=LHAyydsJ;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Sat, 27 Jul 2024 00:52:46 +0800 Adrian Huang <adrianhuang0701@gmail.com> wrote:

> From: Adrian Huang <ahuang12@lenovo.com>
> 
> When compiling kernel source 'make -j $(nproc)' with the up-and-running
> KASAN-enabled kernel on a 256-core machine, the following soft lockup
> is shown:
> 
> ...
>
>         # CPU  DURATION                  FUNCTION CALLS
>         # |     |   |                     |   |   |   |
>           76) $ 50412985 us |    } /* __purge_vmap_area_lazy */
>
> ...
>
>      # CPU  DURATION                  FUNCTION CALLS
>      # |     |   |                     |   |   |   |
>        23) $ 1074942 us  |    } /* __purge_vmap_area_lazy */
>        23) $ 1074950 us  |  } /* drain_vmap_area_work */
> 
>   The worst execution time of drain_vmap_area_work() is about 1 second.

Cool, thanks.

But that's still pretty dreadful and I bet there are other workloads
which will trigger the lockup detector in this path?

(And "avoiding lockup detector warnings" isn't the objective here - the
detector is merely a tool for identifying issues)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240728141851.aece5581f6e13fb6d6280bc4%40linux-foundation.org.

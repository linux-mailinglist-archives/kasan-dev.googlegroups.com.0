Return-Path: <kasan-dev+bncBCT4XGV33UIBBMWR4CGAMGQEEMCLOTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id B4D824578F1
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Nov 2021 23:44:03 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id h15-20020a4a6b4f000000b002b6fa118bfesf6990087oof.18
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Nov 2021 14:44:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637361842; cv=pass;
        d=google.com; s=arc-20160816;
        b=wmvjkbdPmUeX3ul6Rt80EgeCqJ2gQGI4iPM3sD8/6PkwgScylANwTiiKGW1dObrptf
         eAqw0v8PffCdHU45e89RJPe1nao5EeC7Lb8W7vDBJnV65eBt4TygbkEVL8br77YoCeb0
         SoLK6wG0u1UbSc4LDRmzdxTo2O5BknpuFTdxD2G7XkQhRf9WrgJkIZt0LuPcFOTwGHcJ
         mw0ivjGPA+4x9cLkmUwf8lFIYbYNrBmV/kWzHnIYjueVGzeuEOhSGj2tR96Hrq9nQ/KM
         5ln56IGD7FLA1psceaqJ2vWjMciwn2u8N5l4rR2RBePU2yueEGVULyGCoj3+Xj7TQrij
         Kmfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=2vB84AR2yDMod9He/HsB3jaVO3tvVxlFS17RG4+8e6w=;
        b=eEL/m4bLIEINgYhM+TZrqo6SgnkxrzAxbWq3YQimS3ToFdGHQlqFXCo3yr0H7Ah50/
         31gp1V9eos/5PlO9mbQymNAPY7rolkQDhT606iJ7x6hLjaUNy0TLq5fmBkVBbObK0qLS
         mHHUyCc1dHNNwjGmwYsjs05oU4m7BYuU4DY3AiE4rRM8dj3/lhvO9q9WMfOvav3nd+rZ
         uS//2aAba/zXfvXRM8TVKGJdr7BKP4G8LBDvL0xiEsAVCRTbBMK2q5dJ7Hs4vXaQ4HwM
         Bp1vyF5LXbEryqknlih4e7EXVZDdpsm2NS4QPLZVIP2nqiniz4QLrGLr2eCf8wPHMjsf
         nRCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=Fw4+VpZG;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2vB84AR2yDMod9He/HsB3jaVO3tvVxlFS17RG4+8e6w=;
        b=gyxd/u7qwvMm7LXVFu0t88+4eN3Row+ShOFb2rEMu5Nj8/jP9FHSWUbUYOpzt1uEOQ
         /qUfxs2V5cZ7NrF3xKD4P5yWTSko5dTwqwurxhSOvTnqvYmnQ/Lw4GoMhfUe7MGMcEa3
         kgNoARfcFirmZC2X4Jbm5dzSCgkFJ4vB/V4K90nCiyCgbG9229nA5Tan2J74mZjUgPjN
         MvMKA0Bj0hyM/EzX/zOc37GZufx4lwhYbMAjMLsR3XbUTnbxxQBLTxsiPOmSVn22zw/b
         FAOmOrHJkSpvqa0XTPaGbdJdoO6GCFobsyer99RKnAlsJGw4FeuNgfwhloK12MF3qyJS
         oZPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2vB84AR2yDMod9He/HsB3jaVO3tvVxlFS17RG4+8e6w=;
        b=KNVfc+Ytlxy1r96lfv+OhXrC42ArLYCYULQC8TWjBqga8LvDwFGWgecZFBOhVo9NSo
         4GbThKuTtHw6hfVcIxR0v2ejG98QBIuVtLUgLrgn5Vscx006FhDpOys0uBlkbR2wpVuZ
         NJSE4gbPBOiNywxzcsqPbjz/49cFBodyMqcmQaIMOUx/XrUEmSKP2vAXSpSoeFWbcJeU
         YDnR1sHa5sPw4x0n59i8FLmwpRKVt7kQHNNpmNYq40drefU5jv9egMNgMLYTUi9gjxXH
         18IT89tHrnpSZ543Wm74DS1YcCS0lex1MfrcJrttDjCWJ1I4vLcMhl89Ll2Oxs7LgrRR
         Qcsw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532mRd3gOEW+Ap826261n7RJaU8UNFuHkXBbYKzzz8T9nYH5Yjuz
	uZx/TdCUwq19GgK3B6m1ZlU=
X-Google-Smtp-Source: ABdhPJxgD8E3Texg8Q33SDWfvBt0t4FfdofuvFy9RO0iO8Zjguzupc33dWOMdvdbK3rObty1s0UejA==
X-Received: by 2002:a05:6808:2181:: with SMTP id be1mr3043982oib.147.1637361842737;
        Fri, 19 Nov 2021 14:44:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:440e:: with SMTP id q14ls396545otv.0.gmail; Fri, 19
 Nov 2021 14:44:02 -0800 (PST)
X-Received: by 2002:a05:6830:1bfa:: with SMTP id k26mr7669178otb.139.1637361842283;
        Fri, 19 Nov 2021 14:44:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637361842; cv=none;
        d=google.com; s=arc-20160816;
        b=Yt05gE180Ttbbw1JSXXy3Ri3AQmB5obJtGfR399g2muc2Mxh+Y7zla0M4wVSWmr4SP
         1EpKy7oh/x6hze51uNlFwYtPVTbmi1YhoLp2XFevKcV07glt1s881fF82qNQ4r4R3VAR
         0y3LOlYaUUln/t7jhNkq8DKTD9W8/aIP5vRnyFgCX8hPbSsllw5FFUnYzPGNXuD9mPRT
         99b1T5SIHjKVHJkpWFciZHbdQFVk7t/NBS3aSMtJzRNX9DaapsTBoBgHrAm8RhZfWZtU
         rr1VQGO8gWxZvVDF5FvToOe+D88HEZWDrqiQOMatPMVzsCNio0qVPjWU0JxaDqjNSZlG
         oO1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=rHz+JpK41e5qzpmUQ/dtaTXzi6VDv+mN+7GQSZdl9ok=;
        b=S00j9UmS2oP118scSNijWvpCiJ0YDm8uQ40aQbR5BkFheqmUucbATTMYCh7BpURY8F
         O+FJxOS02YsCcVwVV2vt2HJolnyScKCCGRldVZBzaQ9Z8YdYu+6DxLDG62ubNQ0Z5dd5
         JY/jEzWD9U7XhXevpfD4HstuDeMWe4/pEB486KMd5zFQITtzG8STDjezANYbXu6uJauK
         5tAKBLTL01Wob3QYtghGpmrUicRuTOWnDrNu6HsIMM+VoEiwuHrdf/gWzUb6rjvqPHjK
         gXT/zxdyL9lMSVCIEJMkGW5efSzJxIkKCjcAJDTpDwjX0Uw7EgJoYQCyKsxOK2vui92l
         70Pw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=Fw4+VpZG;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id be25si149444oib.3.2021.11.19.14.44.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 19 Nov 2021 14:44:02 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id E767E611F0;
	Fri, 19 Nov 2021 22:44:00 +0000 (UTC)
Date: Fri, 19 Nov 2021 14:43:59 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Catalin Marinas
 <catalin.marinas@arm.com>, Matthias Brugger <matthias.bgg@gmail.com>,
 Chinwen Chang (=?UTF-8?Q?=E5=BC=B5=E9=8C=A6=E6=96=87?=)
 <chinwen.chang@mediatek.com>, Nicholas Tang (=?UTF-8?Q?=E9=84=AD=E7=A7=A6?=
 =?UTF-8?Q?=E8=BC=9D?=) <nicholas.tang@mediatek.com>, James Hsu (
 =?UTF-8?Q?=E5=BE=90=E6=85=B6=E8=96=B0?=) <James.Hsu@mediatek.com>, Yee Lee
 (=?UTF-8?Q?=E6=9D=8E=E5=BB=BA=E8=AA=BC?=) <Yee.Lee@mediatek.com>,
 "linux-mm@kvack.org" <linux-mm@kvack.org>, "linux-kernel@vger.kernel.org"
 <linux-kernel@vger.kernel.org>, "linux-arm-kernel@lists.infradead.org"
 <linux-arm-kernel@lists.infradead.org>,
 "linux-mediatek@lists.infradead.org" <linux-mediatek@lists.infradead.org>,
 kasan-dev <kasan-dev@googlegroups.com>, <kuan-ying.lee@mediatek.com>
Subject: Re: [PATCH] kmemleak: fix kmemleak false positive report with HW
 tag-based kasan enable
Message-Id: <20211119144359.b70d2fde7631bd14cd9652e3@linux-foundation.org>
In-Reply-To: <c5cfd0c41dee93cd923762a6e0d61baea52cec8d.camel@mediatek.com>
References: <20211118054426.4123-1-Kuan-Ying.Lee@mediatek.com>
	<754511d9a0368065768cc3ad8037184d62c3fbd1.camel@mediatek.com>
	<CA+fCnZddknY6XLychkAUkf9eYvEW4z9Oyr8cZb2QfBMDkJ23zg@mail.gmail.com>
	<c5cfd0c41dee93cd923762a6e0d61baea52cec8d.camel@mediatek.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.31; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=Fw4+VpZG;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Fri, 19 Nov 2021 23:12:55 +0800 Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com> wrote:

> > > > Call sequence:
> > > > ptr = kmalloc(size, GFP_KERNEL);
> > > > page = virt_to_page(ptr);
> > > > kfree(page_address(page));
> > > > ptr = kmalloc(size, GFP_KERNEL);
> > 
> > How is this call sequence valid? page_address returns the address of
> > the start of the page, while kmalloced object could have been located
> > in the middle of it.
> 
> Thanks for pointing out. I miss the offset.
> 
> It should be listed as below.
> 
> ptr = kmalloc(size, GFP_KERNEL);
> page = virt_to_page(ptr);
> offset = offset_in_page(ptr);
> kfree(page_address(page) + offset);
> ptr = kmalloc(size, GFP_KERNEL);

I updated the changelog to reflect this.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211119144359.b70d2fde7631bd14cd9652e3%40linux-foundation.org.

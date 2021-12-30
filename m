Return-Path: <kasan-dev+bncBDW2JDUY5AORB2MIXCHAMGQESSBJKNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id 76AF9481F6A
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:11:38 +0100 (CET)
Received: by mail-ua1-x937.google.com with SMTP id x4-20020ab05ac4000000b002f713d873c4sf13247875uae.9
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:11:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891497; cv=pass;
        d=google.com; s=arc-20160816;
        b=PC+b8xiyt3ONC6kQhVmEhik7sf3UkLJShmhBisaMLGCXHdoqdhhNq5vcDLn0e9e7Hq
         cQq5YoC34fXoZm8vawUnTGLZt9m7VkxZjo7ej9CktxwQlRx0FyjtKMRG66/m6AigBnp5
         rgbAW2U5spY3vBw3bmsrqcCuqsSeQtjw396JvP6G1a46t4ggg5nU2/Vt8b+oofw1pgC0
         7ATD1fqtS46YraDkUrx0ADyWWBM4CJt/bzQ31tgjgEn5tl1OcvRA8XsTSRb7mRaoz0HR
         kAjZ3H7rsZn83jUc7hlD74avmg9QKJ7wn6W6XVyfPTr+gRdf2k/S14/EDMMBXVey9cx7
         aqgA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=KRrbskskOgLsFF64/2tq1rQ3xNE0c1TpUoX2IoH2igc=;
        b=0ROf8Gh/v0Wnu8RGYLnwBHGionuqAFPuR16jk1RGuZayvyCDJnz6FZ1SaOFtubzhpa
         Ca/SVObbV3COByMH4PVNOqrEr/sdymNLzWVFNDizaqkFT0tNuu3f4Q/n3JPu6ld9bAf8
         jh0n2nuMFWcsodorR/Z8KetfcCCEU4Q185avf905DKqwXU9WBh7zr5r4c7MSZb0ceiHV
         yLEix0wVijVvEo+pQ/rGfmSZy+B5RCXZj0PQIFLxIiEWTqSi4aQnmZf6G7RY+tgWVOVv
         QNAm9uTujS0duJO6NWd7LaAPCYG0tZRoR50n3NGaombckmf5lIDXli/qfpRJHPXQwI7o
         SNuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="iom+1/8V";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d34 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KRrbskskOgLsFF64/2tq1rQ3xNE0c1TpUoX2IoH2igc=;
        b=UNO2MMyp7F0+niEpnlprfYV5SZnS8ZaXxZ5xQ3vsOyexA4NlUfTbZZhTBm325q8ODi
         PEW3+y7eQn/rVhuObyXQioapHiOL0/vOSemos8NzbfdrqJ/w91LBH7mX+Vz7LGtQ6Mi+
         8Akjbw+wCL9fVhBZ1b7uIaUb59t5crdkRbJoxLhW26ZF+T53gCrJYI1ak2oGQac5obag
         N/Y4chVOwocTYlG3m6lzQif3PZOaLts6Vnkgo9sYJQLk1cI7nlYIhvvplA+NTO7F2WdN
         R6vZRkcB31aVG6A/o2RPwXJBX4BWayr6vNKjW6/tzxhQe57aY+ldRJ8/6wVopiYehhRo
         hAOQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KRrbskskOgLsFF64/2tq1rQ3xNE0c1TpUoX2IoH2igc=;
        b=j3wip1U0I11H/9Y4qrKaC7Z5SeClVsg2qHLpBRf8s3HedCtI0AlaIOQqtnlmXaLfBK
         PYa4gXY6Vnb4SyQfOdMzLq0GGFLLibwFe00o7noecAD7lO5vrCeX/bhpXQLKh/pJRijQ
         MOzQmWkB+qEW/G6+5dGCtJvaJA7sqU2/b7dfHcwa8EQoQIv4QsWjTmh9UNCz17gbPTr8
         332/IvNZlPxxrYPp/TwidPrhswxIB2+yzl4Cfnm5ULwRAvw5AIFaQYXL5qfNI4Qv8rDS
         Q5yDIcFimIKa9J+ZD74XgB6ztLyzEyHt8FryASOeJayy4Lx/HCPIZS0MCCEo7Dt4CX3b
         4iAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KRrbskskOgLsFF64/2tq1rQ3xNE0c1TpUoX2IoH2igc=;
        b=fZow7QHfKJF+Cr9fPXFZ9qNdLEffG9yH7Xb7mlg2B5b6jUV7jOb5CfKW6sxWgBnsDB
         Yets/bAyR7LSzEAT+jIYPFPNzwIl5lD4xei2B1194ksQmk4aiaMg4rUQ6SsAaDC1S7U3
         dJ8H3mlmwHv9T8v/kV4q0Iy1eqYXoFAqMfsIZKb3yol9AZYp7AvwnmNlaoeI6aSFpp26
         gSJzNrPs+3Jbnt7/nAA7gBFqCHwhc94Z13rq4yCrUTGw9RN+2zeSgv+qHWZRt6owX2wf
         bD1TtlX+6ZaX6hYMUTZP3U8WU7QukkTSxw+FHLlTUcOoFoam5E3BkpXne/15BMNf2wNo
         bu7Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5310BZ6/yMevDGDjOtdDgpilxZhd1t8s6PAEppnBLgyDf+R9qXyR
	ctnmJ5lfjmUedqC2gX9V3ew=
X-Google-Smtp-Source: ABdhPJxIFzdMvHxoFuXR5Wo9o6Nlw+HFLytF5umdAyG3KhmFe4nK80clJcMM4ZPzA7h/cR1rg8vGIQ==
X-Received: by 2002:ab0:614c:: with SMTP id w12mr10162541uan.45.1640891497409;
        Thu, 30 Dec 2021 11:11:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6122:999:: with SMTP id g25ls1956571vkd.1.gmail; Thu, 30
 Dec 2021 11:11:36 -0800 (PST)
X-Received: by 2002:ac5:c2d2:: with SMTP id i18mr10776854vkk.29.1640891496890;
        Thu, 30 Dec 2021 11:11:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891496; cv=none;
        d=google.com; s=arc-20160816;
        b=rhUTNzcOhD5W5N5WtLrhKvLVlzhPJjhm3EoN0Ic/oSOKdqkC7Pt8vUyyMW+PY0C9h6
         Ofq1wNhSwGX80+kUAM81R3d+lPyLJ9LC4/QW/Y4dzEPmlCCJ5UkSJmu7FEBC0tQVHMdb
         l4m0pkZEGFFr7LzPZlMt8MP2EyxZYeP07hZoUWWlKCwSyhNNgaQNGCJKVhKHipXAaqnK
         wD7y96U1nbtR++Dqu72tHzOEi5jU6Py2Va4RW+RNCjxEvVxqq4R0/GSTJvF8QNkXIMfw
         OvTxUDWEQChhe3Ymz0AhoFiJhAYLnwtkP1PtHuaLjQ3WdYSDMsAf7DvL/xsN/6olcP7G
         u6Ig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=HzwQpdJfvXsIjvjm8A0dpq6ENpHszfKPhEy/ULrVWJ4=;
        b=phNhzFFr1i8NkEJYoRrDdpkJyWdlYQYOfhhN8ilFvFC1YbN28bLrdaVp3/M11xcuOZ
         4/j1Y2JC68Prg6VT/DymYhmYpUKq5P82tuc70gJsGBjSGYaT4S4pg7D+lBoo4jC1v8Q6
         R0zbl6+ZcOu8ggmwJIGxN8IYOyXbfz9sH4WdjlDExnYN9LvVev/31Co55Mr3sIL9aVPQ
         RMgGh9sabsYxnSOhtf4XPYBYzh4u7yl4P/RApDv1OlqXf35HAkh168uvcpB+eJRLTKmJ
         HaqDRc6hKMbxx1wyx2L1D176GNUGy46D2vQQhNnvCzgvNg/luOn9s4Unx9xTszWRsy2I
         GylA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="iom+1/8V";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d34 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd34.google.com (mail-io1-xd34.google.com. [2607:f8b0:4864:20::d34])
        by gmr-mx.google.com with ESMTPS id s10si1073444vks.3.2021.12.30.11.11.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Dec 2021 11:11:36 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d34 as permitted sender) client-ip=2607:f8b0:4864:20::d34;
Received: by mail-io1-xd34.google.com with SMTP id h23so20465555iol.11
        for <kasan-dev@googlegroups.com>; Thu, 30 Dec 2021 11:11:36 -0800 (PST)
X-Received: by 2002:a02:b11a:: with SMTP id r26mr14612485jah.22.1640891496450;
 Thu, 30 Dec 2021 11:11:36 -0800 (PST)
MIME-Version: 1.0
References: <cover.1640036051.git.andreyknvl@google.com> <92f3029f3647ab355450ed5c8252bad8cfae1e09.1640036051.git.andreyknvl@google.com>
 <CAG_fn=XcPT=e6zmm-B4KQPLujpuC9D+hTbJEsua31onzopDT5g@mail.gmail.com>
In-Reply-To: <CAG_fn=XcPT=e6zmm-B4KQPLujpuC9D+hTbJEsua31onzopDT5g@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 30 Dec 2021 20:11:25 +0100
Message-ID: <CA+fCnZeGDeWFHvkMSQQeG=+DLokssfTjp5hq_QOXrZC0YVd0Zg@mail.gmail.com>
Subject: Re: [PATCH mm v4 07/39] mm: clarify __GFP_ZEROTAGS comment
To: Alexander Potapenko <glider@google.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="iom+1/8V";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d34
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Dec 21, 2021 at 10:17 AM Alexander Potapenko <glider@google.com> wrote:
>
> On Mon, Dec 20, 2021 at 10:59 PM <andrey.konovalov@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
>
> Reviewed-by: Alexander Potapenko <glider@google.com>
>
> >
> > __GFP_ZEROTAGS is intended as an optimization: if memory is zeroed during
> > allocation, it's possible to set memory tags at the same time with little
> > performance impact.
> Perhaps you could mention this intention explicitly in the comment?
> Right now it still doesn't reference performance.

Sure, will do in v5. Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZeGDeWFHvkMSQQeG%3D%2BDLokssfTjp5hq_QOXrZC0YVd0Zg%40mail.gmail.com.

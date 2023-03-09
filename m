Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4GCU2QAMGQEJ5A7LTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe39.google.com (mail-vs1-xe39.google.com [IPv6:2607:f8b0:4864:20::e39])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C4916B1F4B
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Mar 2023 10:05:53 +0100 (CET)
Received: by mail-vs1-xe39.google.com with SMTP id y15-20020a67ebcf000000b0041ed82217a7sf444259vso.6
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Mar 2023 01:05:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678352752; cv=pass;
        d=google.com; s=arc-20160816;
        b=gnWylTTZte2/+L6qI/Qe6cKKgNhBTkclUt6ZLrthQBURMtB9Q0gqN7UhGyY1avacmy
         mKSQnqEoYcehhe1nhpTft5oR2wlrK4ial0b7yoN8tt718vkVVmjUjkVDTg3/b99u+9lZ
         TeugS2YKFOaEjwWy3CTHZ+qKk6zBlZjMu1BjsqLfQWg0mBRh1Hs1x8MvLd+qTLruisLV
         e3BLO2PlftY1GwdDrxrdKqiFlahh17oSC4XHK66hCj8oyjfH91BRTac1/XiOKgr6vbre
         T2Mxj5uMh2pKdwj30dsm0WwjzEQx44a/J0WDZo32WD54qp4DWovBUPBVSKAghzhZceoX
         D7ZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=s1+rvhDi5wemZb8f6WFB70syPZ9p/UlWiBwXJ31Va74=;
        b=FQ4xO5vxPkfPbHwng+NoD21YnxY0gNgPrsd77LhTHeGLyjY0c0KJwGGCjLLBOpxppJ
         jreh/4E/RPMeWwphjzbPvA05GlupswpZFQtTXq7pBs+MT0MS7aswvHTSLY7mmn1zuHj4
         iriyrh/jjGJcWGN/RsejcU3yoLaAZ2OQpBz2mqMupVp2/Ss20VItG0zWYkdcO7ECVJb0
         tw9XW4zMqvS3c51LNNZi444vSJyqdjauzOKi6B9jN/5EVqBaGQv+cqHjBKCHBHFIsITu
         kf28yusS1Sdp/KkIzxsPk01ySWd4LKYAjsVUjQoKFHyrSOorGEPhCyu3BtK9tcuYaXr5
         6YQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=EIqqh4WU;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678352752;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=s1+rvhDi5wemZb8f6WFB70syPZ9p/UlWiBwXJ31Va74=;
        b=BCsSdigpNUxqT2ZzKmqt0LROUs34afmYcpOLaAkKDVoLGGPZT7q16/uLfGODLTs7st
         OCMH6Cxppii3Ohffgdng/B/zfo3VnL9B/l4TDhoSnVjt2FK1oJbfCEbkLnNLIlCBYeqT
         t+DDH5+sUPh2zwtgvlGahiZP2/gtLoRCQJJXWJlZPORPuaZoI/AMkD8WCbV29/vS/nGk
         t/oz1XNeGOVfUTxPGqiVwZKSuAbYdE9GM4hStiuoHNcCbAFwZrdU0xazVW88ChPk0n6d
         QF2Sl1TDlD/ZsDg6/a1d2UM6vc3sVqD29kAfsHHlHpe1YUNov7ZFwZKzbrkiPV2XC1G1
         OvcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678352752;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=s1+rvhDi5wemZb8f6WFB70syPZ9p/UlWiBwXJ31Va74=;
        b=iXXOFMKvWM+qHhoSvJb5YjAm3TlL69/pwPQLE1ODYn8mrbKxGZ+9SH5E8Vt3noLy4o
         TM8dqF1bxC/EW9jCbB6k87rE6lofOELMJhykf8eGjhtEJTDZbqO8S4bZWrmm572bUTBX
         IKU3p3OkebSr+FLBTOVwpCH5Ayzj9laZqTAHSr1ExcVVE+V+hnmqVvoCtzmYoV+75UGJ
         eGITZbxbJtvscTUBeZ/YnSz5+27hZ+ASDkUoz3shc1sg2GUprj22c7Xf0FViIB9jJGUx
         mPGAx1ADDHPkRy0BmHdrmdTh18NPvjJuoQKnP77rf6639XQadKCOA+hTF1PJLqtkGZl9
         C2DA==
X-Gm-Message-State: AO0yUKUINODUHpSOfVFvk2RpwMGZf3ScrN/mqH+M04E6E2ZvI2lk1+g2
	xonrVDq58d+3NAToTCfoA2w=
X-Google-Smtp-Source: AK7set8TLa6idZliig40Bx7o3iy/GJagRqZESjHI1fYH6M/56D1C5/UZrAQyWtKXkowVsIVtWmiczg==
X-Received: by 2002:a67:d583:0:b0:411:fff6:3cc4 with SMTP id m3-20020a67d583000000b00411fff63cc4mr14621898vsj.3.1678352752341;
        Thu, 09 Mar 2023 01:05:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6122:e11:b0:410:c0f7:2273 with SMTP id
 bk17-20020a0561220e1100b00410c0f72273ls188728vkb.9.-pod-prod-gmail; Thu, 09
 Mar 2023 01:05:51 -0800 (PST)
X-Received: by 2002:a05:6122:23a:b0:42d:5036:7703 with SMTP id e26-20020a056122023a00b0042d50367703mr3515246vko.9.1678352751500;
        Thu, 09 Mar 2023 01:05:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678352751; cv=none;
        d=google.com; s=arc-20160816;
        b=SbX4rp80r4EpiITly+1XQ6gKPJ89QNKdAXTqmmBGzdEYy1YVVrFx345e+D4Q0A8Y8h
         ZZVB9QDMMKfJHL0ZUxRNAD3ADJFz/xxjLmfqgrr4nTXfZySXf/mq2eOrdT5jZJ7vRv1S
         Iix2fHcp10Vx8sIHvwuhelaFoDARhL1/ZpgIBQzWyxFoncHWbgMHl/Aq+QK6KCnKo3FT
         9x/tu2yImYAG68EJf7O3VAM/69gqgFeVxl6Y5/Km3UF4I+X58XDwL7mrqW7OP3EqweFL
         lhGXl4q37YqixKpWYesuaJHMW2zde6J0OYL2ptuHQIlTFor8gNQup9IkqRUOzf4SYted
         X8QQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=v8gsX6vrStQeUsH5rKVIzb0ItwKWklQ0bcioQcBInIM=;
        b=OSIUY0zc4YDPHIHkbVVQOdEJqLMCkr+yYFyuMfuYVYZy26icO3aR5vT5/X56dEMTIZ
         ireYyISUxhrMrWGgFoXu/dM0S1sWvQYnNKbC2cpLnJlggl64tOm+IzccJQUzPGbIqzgT
         H44iiqVbVNxs35g9LhxT2w0tIer/imv58oo5eQkRRYB1x4qgqkCM8+fJmQDqMbJwR58G
         prq6iR6SHJgsVaM9kN5XBLVlBcZ2B1uOzJhlWqo85j7ozLrKJ32FfnHWRuItuCPTKssf
         d0Oh84gBo3p2f/hAdEWRjJm9y2cCKIcwqYoczZiY5sWwLMECPn+yy+XKqlRpOCKQhSfH
         AJQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=EIqqh4WU;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x92c.google.com (mail-ua1-x92c.google.com. [2607:f8b0:4864:20::92c])
        by gmr-mx.google.com with ESMTPS id l8-20020a0561020e8800b00414920ce3d2si822283vst.2.2023.03.09.01.05.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Mar 2023 01:05:51 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92c as permitted sender) client-ip=2607:f8b0:4864:20::92c;
Received: by mail-ua1-x92c.google.com with SMTP id n4so634309ual.13
        for <kasan-dev@googlegroups.com>; Thu, 09 Mar 2023 01:05:51 -0800 (PST)
X-Received: by 2002:a9f:3001:0:b0:68b:817b:eec8 with SMTP id
 h1-20020a9f3001000000b0068b817beec8mr13953524uab.0.1678352751125; Thu, 09 Mar
 2023 01:05:51 -0800 (PST)
MIME-Version: 1.0
References: <ZAhkQUmvf1U3H4nR@elver.google.com> <20230309005831.52154-1-haibo.li@mediatek.com>
In-Reply-To: <20230309005831.52154-1-haibo.li@mediatek.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Mar 2023 10:05:11 +0100
Message-ID: <CANpmjNNw6utf5ozpwu1keDG92Ew_vL6B=LZoRw12p48eVJeNnw@mail.gmail.com>
Subject: Re: [PATCH] kcsan:fix alignment_fault when read unaligned
 instrumented memory
To: Haibo Li <haibo.li@mediatek.com>
Cc: angelogioacchino.delregno@collabora.com, dvyukov@google.com, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-kernel@vger.kernel.org, linux-mediatek@lists.infradead.org, 
	mark.rutland@arm.com, matthias.bgg@gmail.com, will@kernel.org, 
	xiaoming.yu@mediatek.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=EIqqh4WU;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92c as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, 9 Mar 2023 at 01:58, 'Haibo Li' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
[...]
>
> The below patch works well on linux-5.15+arm64.

Thank you, glad to hear - may I add your Tested-by?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNw6utf5ozpwu1keDG92Ew_vL6B%3DLZoRw12p48eVJeNnw%40mail.gmail.com.

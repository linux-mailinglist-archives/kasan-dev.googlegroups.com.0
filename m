Return-Path: <kasan-dev+bncBCCMH5WKTMGRBY6A76OQMGQEKO2LQ3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id B0DDA666F8A
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:26:45 +0100 (CET)
Received: by mail-ot1-x33b.google.com with SMTP id e25-20020a05683013d900b00684a1d326e5sf3554855otq.13
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 02:26:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673519204; cv=pass;
        d=google.com; s=arc-20160816;
        b=ID9DJFJYsMAWKzPzSf29bgMtIzGTS8RWqO/x2rJ2ByiohKNyFO3gph9DE9gs8zlX4Z
         R5G8bIWSHXG0iyy/YRfLVRFs1n+psLo1pNdY3BoVDfuDEknWvxAlE8w8NXYSkF2WOjgC
         Q81i3HN6NDcr5m52/RPaQrgcAyMfvjK4OGfT6o5CMtX16aucCDNeugHupAJY6ZOlMnaD
         OAlyhljvO+8SJ3Jp6CjzVwoo3Y/3eGfrvV7K/VfwkJRw1mM/RonodffXS/vKWQjpiXwb
         Dg7+V4sGD4mZjPlLKpKnPoMp4MDvP+feqZdaRyJaHKBLJWyaDgwHb4aIWTxBlhHt9GBg
         /0jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=tXvsy/ilisS5C+tuzoJWy10/99NcJie/dfiuXV9WL20=;
        b=EqiM1+YXVjzWSp5vFGaEfbI7BwEOUHDEI3PGAh1peOr+P5T8KSj/AwvKBkpR168pId
         hLscWySahj93WF1mXBC0/Zfv+YD+TmGEsMpLuaaZMtsvT8+CLJ8AWbcF2F7nmGLS5Zwi
         5EdjwXzhcKp808bDMcWJuAuVN4Y5QFQtV0jIz7pjio2/qmZpBkCEmeEIMYwKPvZWrfsJ
         rQDCXy1uoxLCxucgyMI0HtEC/cqk57b6wenBuY+bmxWUhQ0v39wrbzkBFXrO6uaKYDYO
         zv9OLXRjNIX/A4DQ08TyyKMsB9yD5AHvGiXLH/slWg/WBUZZiyI8FT33V3334rv37v+z
         oeeQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=WUIs1LZA;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tXvsy/ilisS5C+tuzoJWy10/99NcJie/dfiuXV9WL20=;
        b=QheHQJ5dE4Sy9dYe6LsutDna0P688Z9x01kXNzZQrwxUAZ7D5HLiqY3GNZbJU29hwu
         aBBvHo6B4wEbaSmagnK0oWsSPXJWbR3RjxHkguys/vQ2i7RrIQUYWzWEFqdiHieYKHv6
         jCA/gDOmaVipjvhjO/0imYhJzRcQI7BovJ0L7TbveDqkJtWv18G/pSsUmzxqmvg3Udlo
         1jshrLnC1zNs8J4iXNQVEdv9zGhb/loq3HVirqmhNfYahjp0HLmDSaN6cUTsJfdANEWv
         vZQTw+GxUyGJwWlt4J0q6e0ZNO+Vo9KsZ0BuD5wldociidOd+GDUKJc2UO/9LVvjUzPq
         UhwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=tXvsy/ilisS5C+tuzoJWy10/99NcJie/dfiuXV9WL20=;
        b=T5ALEcsly9RfI8Z+bE48nDVMDSJA9hZOfpp+FdoWD8UM/9AufaP21aZ2wcMBdg8ApO
         +OSjHx8BIkvtarBflkpm1ZDReuGh8C+ZJlORouyoEcvdYr/cDOj+N/84UQyQuTDSeyLg
         1gbbKtuw1VOoCkbEVeGHKRjLQrm1SpS+CxTl74O++PAxRIqanQIAh6nE4oUOH6jBEiW7
         zJU9VLwO6DcLIA9UNLt8Z12dPPd8kyLQ7L75XI8oLxA/AYY3caANxMqVBU2/BiSTJIzq
         A2kAT5bW8De+18kKK+v/J+nXOHJO0xVPK/smisPjwJ+dQ3NXbX71kMKoLmGrgUcatgrv
         ZqLg==
X-Gm-Message-State: AFqh2kqdv7dTXuVpaWJkQYxpncH9G8h9oXnKdgHWkEkKWPyqve4bfBCP
	t7IW5yzUuOfZTNdvHZWt604=
X-Google-Smtp-Source: AMrXdXv2MAx2W2LOMlN202C9x6D1RMT4K9j0fT48P2zb0SE0wSETLQlZS10tVWaF9cK2pxL4K7Iryg==
X-Received: by 2002:a05:6808:3a85:b0:35b:e3c4:afed with SMTP id fb5-20020a0568083a8500b0035be3c4afedmr5702874oib.44.1673519204030;
        Thu, 12 Jan 2023 02:26:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:120c:0:b0:35a:f69:4b04 with SMTP id 12-20020aca120c000000b0035a0f694b04ls434836ois.6.-pod-prod-gmail;
 Thu, 12 Jan 2023 02:26:43 -0800 (PST)
X-Received: by 2002:a05:6808:6395:b0:364:a3c:ae89 with SMTP id ec21-20020a056808639500b003640a3cae89mr9940198oib.56.1673519203603;
        Thu, 12 Jan 2023 02:26:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673519203; cv=none;
        d=google.com; s=arc-20160816;
        b=l+x+Jdhat2b6gMKSjiuvCCiYWnlTil+BTuUX0Zq2q9e/zc1cXFMxgu0F+Ryk8c0hat
         hm5cW9mlvjAHPTSOHOIVELCTI+JvXcmdEMHnYw8zRCURAhoVxiIpvR9AlAj8pwHoL95I
         ZfN5+h7sMIIyL8Vtu46v2IaVqtpYufDytH3Sc0Om7KwjoqlNBStnTDFow89Pgy9+R1x8
         oc05nLSJhOOteLvUZ+1tQg/2xpD66KGwTvqtAokR0j8zNkNcM4JM8+23llliJj9tb/sK
         tyjt0u+9cmGXLWPmA8OkRNX7Lx2QmBaj8FRM4a49fiLysx2qaHaTISB+sZq3enloOIU5
         CXXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fG/qOjXUfppGChnP3Lxtdh/yMmyW83w+zHL2i0LLc24=;
        b=uGfTV5h4iSIYJWIWE467ohptQiGYB8hNdBWU7uY8Gc/OJKr7phrhl8hqSufh0WuTem
         D5Nym1RMxoo++IPPsbIJQ4KYrngoeTdAFW3Ce8wCLmnER5FjxVVqYxj6gG4+jbp6L5kL
         FEDnhqbOGkWz9LrPuzkZYqe65xIjolC1VZTFdUCto7FYpy81eEL7AVPWtttszai7qxHz
         Q0Kya7oGy+GPI1hX1CIdnCkH8LSz7RylpyJ5UNGkQxbyXzapLdp3Hy3ibJme6zTlq9cq
         D1y/QXPyt4kNROEqEk5rAS1+TbPKWtnVjw4w/is+gvSKgcoQVHjfK/H5xkm46M9GceUr
         yApw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=WUIs1LZA;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112e as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112e.google.com (mail-yw1-x112e.google.com. [2607:f8b0:4864:20::112e])
        by gmr-mx.google.com with ESMTPS id n132-20020acaef8a000000b003645c7e411csi539786oih.0.2023.01.12.02.26.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Jan 2023 02:26:43 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112e as permitted sender) client-ip=2607:f8b0:4864:20::112e;
Received: by mail-yw1-x112e.google.com with SMTP id 00721157ae682-4db05a4db9bso10057337b3.10
        for <kasan-dev@googlegroups.com>; Thu, 12 Jan 2023 02:26:43 -0800 (PST)
X-Received: by 2002:a0d:e60b:0:b0:3ec:2e89:409c with SMTP id
 p11-20020a0de60b000000b003ec2e89409cmr2098736ywe.20.1673519203165; Thu, 12
 Jan 2023 02:26:43 -0800 (PST)
MIME-Version: 1.0
References: <202301020356.dFruA4I5-lkp@intel.com> <aa722a69-8493-b449-c80c-a7cc1cf8a1b6@suse.cz>
 <CAG_fn=XmHKvpev4Gxv=SFOf2Kz0AwiuudXPqPjVJJo2gN=yOcg@mail.gmail.com>
 <953dda90-5a73-01f0-e5b7-2607e67dec13@suse.cz> <CAG_fn=Vz47zvCDoUENX5kH7Giena+w=yifWbMo28ayAUKU7kyQ@mail.gmail.com>
In-Reply-To: <CAG_fn=Vz47zvCDoUENX5kH7Giena+w=yifWbMo28ayAUKU7kyQ@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Jan 2023 11:26:04 +0100
Message-ID: <CAG_fn=UvnHd_gVuqkWEC9RLBUjreD-BC8sb67nLD=bq+SP7Zfw@mail.gmail.com>
Subject: Re: mm/kmsan/instrumentation.c:41:26: warning: no previous prototype
 for function '__msan_metadata_ptr_for_load_n'
To: Vlastimil Babka <vbabka@suse.cz>
Cc: kernel test robot <lkp@intel.com>, llvm@lists.linux.dev, oe-kbuild-all@lists.linux.dev, 
	linux-kernel@vger.kernel.org, Christoph Lameter <cl@linux-foundation.org>, 
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=WUIs1LZA;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::112e
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

On Thu, Jan 12, 2023 at 10:15 AM Alexander Potapenko <glider@google.com> wrote:
>
> > > Would it also make sense to exclude KMSAN with CONFIG_SLUB_TINY?
> >
> > If the root causes are fixed, then it's not necessary? AFAIK SLUB_TINY only
> > indirectly caused KMSAN to be newly enabled in some configs, but there's no
> > fundamental incompatibility that I know of.
>
> So far I couldn't manage to boot KMSAN with SLUB_TINY, it just dies
> somewhere very early with the following stacktrace:

False alarm, a reduced config works fine with both KMSAN and
SLUB_TINY. Perhaps the one I was trying previously was too heavy.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DUvnHd_gVuqkWEC9RLBUjreD-BC8sb67nLD%3Dbq%2BSP7Zfw%40mail.gmail.com.

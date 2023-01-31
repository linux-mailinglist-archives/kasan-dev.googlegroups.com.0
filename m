Return-Path: <kasan-dev+bncBCCMH5WKTMGRBX7Z4OPAMGQEUGZLJ6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 07408682B92
	for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 12:34:57 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id dz24-20020a056808439800b0036ae9f31d8csf6195621oib.13
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 03:34:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675164896; cv=pass;
        d=google.com; s=arc-20160816;
        b=eAo6TGm2Xq2yo9kerzOkI813rZx3D/+pP9bKU4XMGyePIAijnT9oDvu2VSZDvO7xsl
         rIofhSGYE09E9IMndC9dLIvqT1ee29aREzYcjs78MLxKURYNoFrzIbMMporMIjVzy24S
         DXfJX/e/cwRliW81XgTyCSwOWXNwEYjlCXlTw54RK1v+JAY9i6YnETzJiGrIjQnDqntC
         DmwjSNCk4y6lhDvF/qPZX1u4VRh9LzFCjBx+76LSm1PBQGg8DOGknJGZZXff1CrgVVzz
         1/Ywau4iej04HDRr5P7AJbvWLSddQPNraIzoZZcaiyqaf97e82ClqFfCZ4ftzbIJ0ZQP
         Ec1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=9UafZQGFqpM3/ckqFsq2vhENnuleuHJeQ2TEYIrg97c=;
        b=ymnWrk/VpPcWO8pBrFF0Krtghzkkkty9Cszu65ryeB9SonYd6HBlHlgbRJua4ABYDe
         +Yxer3/H3YmJwCwCH8iYBu3T3AulpgEgsmZu2y0sipbd74YrBzR5+1aVv60mt+6BY66I
         ZyLrMRfdMW8US0Io0GVL7ujGsENBM/hZuLWYm1xTDHPOnjBqvuoYgzd2hXKlLEbAxgpF
         SWprjB9E7kJNp9+QwXigGiKFe6SwxUWIrQONHnTsiQYRMCiyf50bA1Y2SMVIZ5f1mNfY
         /2z1Z3uLG+4mo0wnR8L+8YsnO0yvhraqyI4sYPbmTc4XZiubNRa9caw434YJFJ/oJw+H
         QD2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gwtEvNWV;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::a2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9UafZQGFqpM3/ckqFsq2vhENnuleuHJeQ2TEYIrg97c=;
        b=jhg1hpLMMkzdhSCTJy0KVLxgbPqBXc+Gvjc+MNQ4u6F2d7nyiy9fhs6YHrvjTwBZZS
         QaovLGjmemykHMHT5c1q1PY8ts9yhuswIRQin/6k8FNIJ44QZTkOv900sBrSZdqVD6e3
         AP8IUZYL+tYfQHv0mYLifgfTgp9Pg3kUqldAnhxchRC6Ekvb5K6QzNXQisPVn0paFV8r
         mlq7a5mxVZj4Glrh4mClKKvKMZncKBS4/tXftxXWSG4oodQtYFHEQzT5y8W6Ayt5IuDZ
         +CJyz1MUDwcP4RdD1W7+U/ipjhfdQsfMH++RNXkwJk17Dvwtv++hLf3YEzdlKtXoNa7i
         I3gQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=9UafZQGFqpM3/ckqFsq2vhENnuleuHJeQ2TEYIrg97c=;
        b=B+o+8a35rBBuwmRvJ88ulWWj30aBLaWKXJLdik57r0YhRPSObGMKOLIBuGMjTObNaT
         NMPHNz71/7wEfOecZm7Ve9QlFcjA7L8VvGJqrZwgiSwGIC+PKGIUZvVUZIzMZBZPItus
         0x8NY3mTDIwxTm1jAtMEh8VI2aQXQjBmxwxZN4G6qELAOIWr0ycwVa4H2M6G1uPJg3Un
         4TqyXC59/hRh8hq6ufg80MY5MeUq7VB8vQs8fcAXiSRYYzNtGnfZ1mnc8my5HV/ICWil
         eNu86W+NwahzX3bQzP0Fi4Ydl1TqalNhRPh/dqfvRaOq4tlkv0nRIv4VDbuep4bM/uyX
         RCWw==
X-Gm-Message-State: AO0yUKWsoS66OPPky5CwMa++bwj9Xc0uWvmKcd3jHEb0vttjaCCMaLhT
	z4sAdGIl/2e8T6GEllY10Qs=
X-Google-Smtp-Source: AK7set/yi/gJum+M4M8uJqiDlapmCOVJKCQM09WUTE54Aqit4UqYijfViW4bXUTWRg4cFhEeI5kj+w==
X-Received: by 2002:a05:6870:24a2:b0:163:5b7c:3c86 with SMTP id s34-20020a05687024a200b001635b7c3c86mr1454776oaq.19.1675164895948;
        Tue, 31 Jan 2023 03:34:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:6301:b0:661:b84b:eb5e with SMTP id
 cg1-20020a056830630100b00661b84beb5els2143571otb.3.-pod-prod-gmail; Tue, 31
 Jan 2023 03:34:55 -0800 (PST)
X-Received: by 2002:a05:6830:30b7:b0:68b:ba9b:5ac5 with SMTP id g55-20020a05683030b700b0068bba9b5ac5mr6764205ots.18.1675164895578;
        Tue, 31 Jan 2023 03:34:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675164895; cv=none;
        d=google.com; s=arc-20160816;
        b=hPGlDs4ZW5+I68IfbRe5mZa2C5TkWpGDHkLFTdqznZepQyJuvH7YduzMxc0f7kmjAk
         wPwnQxmjraP7Vn4g+8gTM82+qjrRg3Z3B5DFXq0MMrFj5qsSeBmOn0iAMZ8mrsUq7YuS
         1sAAmnrmcbozzXL4dAfswh9F5wYiAOPKnpTKfPlyvEdzKI4CNNol3Ibq4MILT0ggflyR
         nIKX+9Mf2mOht2uAfQn29xYuzsE2xVVaq7x2sJzffhKmEXH7rDBGanq+K4WZsf9XQ5kL
         km5Wy362mZyk9Oa4EMDRbG8ysMYwfXTTonoi+Kp1LRE40n8I6WnmBMJwLcnKGwy3Y0DD
         eEfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2XA9F8dT5La7FNowNfZ+ob9NzupifQzUI33ZbhcRFf8=;
        b=K573EIUz41gzTCOHxCfy7wqRE3PBiyL5vuaxuCHAaXOpRXy6bTBSCXTTAh3ORV7IAd
         xe1aRyfomo95k9mba30dTJiiEWlU9/3B4FW1Y0Hgk+GEx/tdFtMYwr4JbLEjZshl0ZU8
         49xiyeNGSWUv6RFfggvc0VGrTZKUY1bZfdTYqQCBSS0rEixL5tC3CZjg4gXoV3poE2mn
         yBdsdT2F92wpkL1q/fbIIDRgB57h9VEGOW4Tv0fy17Sq4t9fDrX+IrC6teGMUYzAbKKk
         JBR+HBOjXOQoAGCx+TwWCL86BaEX7sVODZ6wroHvwsJAeY2oAOUPt9NvyzUizBfB/xRM
         h0+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gwtEvNWV;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::a2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa2b.google.com (mail-vk1-xa2b.google.com. [2607:f8b0:4864:20::a2b])
        by gmr-mx.google.com with ESMTPS id br28-20020a056830391c00b00686566f6f48si1769061otb.0.2023.01.31.03.34.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 31 Jan 2023 03:34:55 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::a2b as permitted sender) client-ip=2607:f8b0:4864:20::a2b;
Received: by mail-vk1-xa2b.google.com with SMTP id s76so1884972vkb.9
        for <kasan-dev@googlegroups.com>; Tue, 31 Jan 2023 03:34:55 -0800 (PST)
X-Received: by 2002:a1f:d187:0:b0:3e7:295d:64d8 with SMTP id
 i129-20020a1fd187000000b003e7295d64d8mr2731185vkg.35.1675164894961; Tue, 31
 Jan 2023 03:34:54 -0800 (PST)
MIME-Version: 1.0
References: <cover.1675111415.git.andreyknvl@google.com> <b756e381a3526c6e59cb68c53ac0f172ddd22776.1675111415.git.andreyknvl@google.com>
In-Reply-To: <b756e381a3526c6e59cb68c53ac0f172ddd22776.1675111415.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 31 Jan 2023 12:34:18 +0100
Message-ID: <CAG_fn=UN-K2W9E+q=tHheda8BGCzoPg5-riXpDyiSaLqjekNkw@mail.gmail.com>
Subject: Re: [PATCH 10/18] lib/stackdepot: rename init_stack_slab
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=gwtEvNWV;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::a2b as
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
> Rename init_stack_slab to depot_init_slab to align the name with
> depot_alloc_stack.
>
> No functional changes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DUN-K2W9E%2Bq%3DtHheda8BGCzoPg5-riXpDyiSaLqjekNkw%40mail.gmail.com.

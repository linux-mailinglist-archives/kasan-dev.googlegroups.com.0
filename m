Return-Path: <kasan-dev+bncBDGZTDNQ3ICBBG7IXGSQMGQEBDIWADQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id A43FB750356
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Jul 2023 11:36:28 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-3461839c3f6sf30523525ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Jul 2023 02:36:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689154587; cv=pass;
        d=google.com; s=arc-20160816;
        b=qPaKYpjVWIwcQyw9EklZAt5buycaYDhqQIRwvPejfjw5VCCsYEgQ5biEnIkcruwThv
         2x2fim8Q9r0ZSZ7cyhwkXjFVa+idMHU5iJFeRtRy1yz+JmSL7qlOu9NDB5kcHsIgL8wO
         LBpQYylsptea7agMJV5GBnyEj+aEJuYVAUAOENCxeknY+x1MGUgYZ33WwQNGM7PHkKzY
         bBE57gx9n4MXTHGxz+ILDFHK03MrwT/fNaHhtZ/YTMtVzzPSwE7iTtwjhg/VaXwVQq0i
         HRJxVYqhDDQyYADKqmFs70VlfNAp/RC72HkV4jNmJlOPZFBX1j8sPkrWFCqkPM6Dmoul
         HleA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=We62TSeB5+p0tedoh0LnE64U8YKRAFkRgmnGMxT6MZw=;
        fh=qaTgcxw1t+XO8eb7IlA13DofIbUHoHaPKRBFwRBPJDg=;
        b=mPB0ktHC3Ly+aBAnOxsdfJ0Qd/8yGh+k9mOTnrlHqnaPkPx47QYw+EV+qHNXO/Jw7X
         AsJj4nCPBgcFoVlxmyz8NUpikb+eY2oPPj8GINfAjHI+ItOlS+wHLIO7OqrRGC7a2Sl7
         WnlqhLZp5tOymP6rbi9UNscQ2Nxdtgl2dE2H/fw5YqK0Tr1GZTp238p5SeQZkzz23aeW
         YUFUZrm8NGTcFuKU2iFGaIXRBOhURv8IBj0nda0rlraqQ66srNufI+sbHZh6UurSvWYX
         qXZrb+1b1tGNUiFjITBMgGLTIxby4FLwL6LPqYADrKIL+4ucbhYEPHyttoPmWtbUhBwU
         +sVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=GKmJfOeI;
       spf=pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689154587; x=1691746587;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:from:to:cc:subject:date
         :message-id:reply-to;
        bh=We62TSeB5+p0tedoh0LnE64U8YKRAFkRgmnGMxT6MZw=;
        b=tVT7TwEdVbst5u2wan7PYGu3a7/iUhnzziqt+UUAbYcKmcOERX0a/2KOKBI0oR4bOu
         Qp+0HJGwH1ODzq6cyYpEGzdhKxLDLrCY9qyb+P1AB+bjejTOsO+JXqQgjUgs4l8E9tde
         or8s8Jh7YpfurSjzttPz+ITbdbZ78gsETbf3/bEQ6yM9kJ6RfJ5sON6ZYJHau76juSF7
         QY2BzVd/OGt/q1Gog+lr6n9GYtXhOFGarq0Isod6l4+Qp0BzqDmR07wXrOHD9qnxDKPY
         XKI5iOfmK6J1ZVIsPd43lPvyKS+E+8H0a/5VjZFQsfKsO0BRf6h+O06IahrKLgN28Yid
         3Zbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689154587; x=1691746587;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=We62TSeB5+p0tedoh0LnE64U8YKRAFkRgmnGMxT6MZw=;
        b=F5HFew95lgFoXna9Vz5VHaxGX3AMj3//3bl1F1UyGb4P7rhYOnIh7dar0/ckLQYb8k
         PoEP/fQ6j9ufb0+6tSF96D3RLoGI1Zqy8zDUkRvVXhwxjaez1Bmm2I89xvHWHufGlZTN
         KOt1vgZpYJpGFi9FZb6fUj+A5JpDAOXYUTruwdSmzinLrNUOJ287OTbqx2DyllM0Ipbi
         XfRZXBHTWrNGDxiltD5n7YcTpekwuo163Zq+j/NfJ8zJl83//dmx2vXazEzTklyz63eD
         D2W9rgDqwGuPVoPgMELMwpVnqhtmA4etdxif8vdqtNdmFRRMLbMy6gFBSTX6hhRNE6Qx
         fzEg==
X-Gm-Message-State: ABy/qLYzFAmbkkNcrIf5F0k9eAf4cS7qv2TU5ax8zVssqcMdqTrZtlWS
	Wi4te1GlEmFXXVUsUm0f1uQ=
X-Google-Smtp-Source: APBJJlE0eGCXXBxuq2EQz3Mjf6uLvvfKk1osuqnvb19erx0eMX7x9N1ydJXQdRvMZsQ0vYE/3QXYdA==
X-Received: by 2002:a92:cf41:0:b0:345:cdbe:833c with SMTP id c1-20020a92cf41000000b00345cdbe833cmr14789981ilr.28.1689154587221;
        Wed, 12 Jul 2023 02:36:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1d8e:b0:346:7cd6:b86c with SMTP id
 h14-20020a056e021d8e00b003467cd6b86cls19075ila.2.-pod-prod-04-us; Wed, 12 Jul
 2023 02:36:26 -0700 (PDT)
X-Received: by 2002:a6b:dc0c:0:b0:786:e0d0:78b4 with SMTP id s12-20020a6bdc0c000000b00786e0d078b4mr14655482ioc.9.1689154586714;
        Wed, 12 Jul 2023 02:36:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689154586; cv=none;
        d=google.com; s=arc-20160816;
        b=u9nIi2C000Wr+5SVJwdHr41LPLRDB8R08grhFvdrgxLfvOqUKeqiJVOBw4njgVvRIZ
         QWZUHgVi4tLAl8NGLHcHvVC1epv4DjxmO7yjeqrrvyuZcJg1OwTQ2u4Ot+Ju/7ky13/d
         FRlpD5hwx7qpyMnsqgpf9wjuC2EVUGnHCbobCKhVpfMEnTEHL1y4HXMDZCUAm/bWKOuZ
         0EkPJp0fJar2H1A0riBLvFhQ1MBcpkcn7dfsvaO0itaXp5lE6c1o7L14/sa+xEKy12JR
         hmem7dx2wInnOMh+FC9rhLNUtZDAZU5n52hljlva1FvNcEu90RktQAx6hniWBKjNyg38
         Xx4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=BFHWPlgRbtTouEuL3TeQmFRHeduzwEODVigacZ0+gS4=;
        fh=ze3n4caySbxAHVqHDChZBUej/9vsC83YAndyDuHgKKU=;
        b=hpJUHPG/qXx1MrL0/QOmoJPzxPuOXHrz+42Udn5MnDyqMJrI00Enicx/G84gePRCBf
         2bNAxSAR9gryPtaI+f9Fy7fJ45ZTRIBdoq1lngI1BsKTuFaz2toE5lTKSM0nUKTpqsWB
         npGJecHjezj1j4bxf6uDqz9AE/OhdnWwKJ+98S8Q+5c3LgFAl4BA/3SaBsp8eCBX5rOr
         yljjzZVDQy1D+bm2Y/q0SfXJtWYznmH7dGwfsbVxEK5CNEMoz8f/3cz6TMNkwCyDsDJ3
         ziELj4jcep0IHwRrysdAyzK1AVOZ1tC087Tag87FUhfdU02mh1WJ4J6IYSrEjsNJG/BD
         iyIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=GKmJfOeI;
       spf=pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
Received: from mail-pf1-x433.google.com (mail-pf1-x433.google.com. [2607:f8b0:4864:20::433])
        by gmr-mx.google.com with ESMTPS id h15-20020a056602154f00b00786deceee7esi208507iow.3.2023.07.12.02.36.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Jul 2023 02:36:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::433 as permitted sender) client-ip=2607:f8b0:4864:20::433;
Received: by mail-pf1-x433.google.com with SMTP id d2e1a72fcca58-6687466137bso4636637b3a.0
        for <kasan-dev@googlegroups.com>; Wed, 12 Jul 2023 02:36:26 -0700 (PDT)
X-Received: by 2002:a05:6a20:418:b0:112:cf5:d5fb with SMTP id a24-20020a056a20041800b001120cf5d5fbmr11212751pza.50.1689154585901;
        Wed, 12 Jul 2023 02:36:25 -0700 (PDT)
Received: from [10.254.22.102] ([139.177.225.243])
        by smtp.gmail.com with ESMTPSA id p1-20020a639501000000b0054fe07d2f3dsm2973750pgd.11.2023.07.12.02.36.22
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Jul 2023 02:36:25 -0700 (PDT)
Message-ID: <e38e8525-3e9c-8925-2160-228875183f28@bytedance.com>
Date: Wed, 12 Jul 2023 17:36:20 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:102.0)
 Gecko/20100101 Thunderbird/102.13.0
Subject: Re: [PATCH v2] mm: kfence: allocate kfence_metadata at runtime
To: Alexander Potapenko <glider@google.com>
Cc: elver@google.com, dvyukov@google.com, akpm@linux-foundation.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, muchun.song@linux.dev,
 Peng Zhang <zhangpeng.00@bytedance.com>
References: <20230712081616.45177-1-zhangpeng.00@bytedance.com>
 <CAG_fn=Vj+rqkz0_3kvBoBVoxET10KV-zoD=YtJmCfsA8YEMemg@mail.gmail.com>
From: "'Peng Zhang' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <CAG_fn=Vj+rqkz0_3kvBoBVoxET10KV-zoD=YtJmCfsA8YEMemg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: zhangpeng.00@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance.com header.s=google header.b=GKmJfOeI;       spf=pass
 (google.com: domain of zhangpeng.00@bytedance.com designates
 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
X-Original-From: Peng Zhang <zhangpeng.00@bytedance.com>
Reply-To: Peng Zhang <zhangpeng.00@bytedance.com>
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



=E5=9C=A8 2023/7/12 17:30, Alexander Potapenko =E5=86=99=E9=81=93:
>> Below is the numbers obtained in qemu (with default 256 objects).
>> before: Memory: 8134692K/8388080K available (3668K bss)
>> after: Memory: 8136740K/8388080K available (1620K bss)
>> More than expected, it saves 2MB memory. It can be seen that the size
>> of the .bss section has changed, possibly because it affects the linker.
>=20
> The size of .bss should only change by ~288K. Perhaps it has crossed
> the alignment boundary for .bss, but this effect cannot be guaranteed
> and does not depend exclusively on this patch.
> I suggest that you omit these lines from the patch description, as
> they may confuse the readers.
Ok, I'll revise it to avoid confusion.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/e38e8525-3e9c-8925-2160-228875183f28%40bytedance.com.

Return-Path: <kasan-dev+bncBDYJPJO25UGBBS473WTQMGQE3JICGZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id E4C7579243F
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Sep 2023 17:57:01 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-26f51613d05sf2759251a91.2
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Sep 2023 08:57:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693929420; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ka8Cd5DSEBe4Ir7lOjfQrN1OvUUD5h32rY5+jKrbFh3zh3jNxNneaQ6dXq3xaFwhTX
         gEZUSJUvClomr+LUC+sumyLV9fGE3taU78Xod9Zt9UIcRHfIUhEDrgCqfi+8xqEdXU/t
         p0v/YZNgXU4uCtLmciLiOoyGsfM8zb5zIF5Fjs4n3nSdFLKoIwNZvziL6Ea0UEfzthYz
         dXck5WPrBS7Q3GbfODAFLnpH9cgPWkOVCWhS1TOxVz7y1xPtvmlCNbMfs5nHNpy8GFqm
         eYla0UNzoZTXkYZT1OPKp4wwb09Dn3irKHrW4phoZAlPvRuDEmYaXIGFMwvhV8rFNdjT
         UCkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZabqQhdcwQfemaBHHDPcVldqd9+Pb7cs3lThjpZ70ow=;
        fh=N3XWbtwaVQKP5OvYRmyh8XEuRlJ1WAqGcqs7JAhSeUk=;
        b=Fz88/1BAK/0KxjDCPRHwbyGoFXmO8AXOVBvdmc2VajRJM/x7UbtulCz7pOUR/j4EO/
         h59yBFXEcuVnyWnfInY7MPo21OzpK5Bs6bPbw3nScxeBLFQvcWnUq7hkgGR0S+rtyMZ+
         aQKEq3F+SDD+EqXw0xEbbX2gEGM742Z4a51FmPPiiCjC1CAtPJ977tsfeqs2XRJ+0ev/
         iwnIBLO59wuFKz5JivIhWRVd8K97vcEXrp4ksXDI6TywEoUNJ8H/eTL2VqPTKDKTalMK
         GRVLDe/NSwxq9yhHlGl+drSd/rYxIsBpQB+g6fI5FEZjOawcl0h+MzbmqwVj96s8wRus
         7Vhg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=HsZUMGHD;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::32b as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1693929420; x=1694534220; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZabqQhdcwQfemaBHHDPcVldqd9+Pb7cs3lThjpZ70ow=;
        b=c/v4v+nUMLQ8Kyxfvl/jfufjg9kKnvYM5TBpIAMm67B9VECvwLRuqkKPHfrLzwFIYF
         S10gnb0hTJkiKhm4yct3Txy7B19pbOEhdYgAcZV2vbuy7iPySwsQfdMa3BtORAc3cCsU
         a8hdzG4zYYS0pbflIxi9LTiUFpf99noPbvydSeac6k7D9e0oyJgz0Vh4IfLYBveW0mf+
         N6vUbCU2APDvXT+6BUjoPiCxWmPD9OcgyODIYjOykFIEunF0E0vr0r+8BFwONwFtE5Xh
         MjMcswmVKuN3SVE1CG9ac3s1irWuWy6NvtCHcFmf5YsaLjzEUKBWdpD06RDmOy+xH6xE
         gf4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693929420; x=1694534220;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ZabqQhdcwQfemaBHHDPcVldqd9+Pb7cs3lThjpZ70ow=;
        b=PtgxfY+egVkeMeobASfBgUSzzDzRYa3u1xnG8qN3VCZVCKXs4RXpKfqppQrJ2eGhmq
         zlJZooVJCQtBvK7jgqqZYTau6X+klQ/196mRv0QSM8Ka0h9BAY5DCmo8+y15kPFar/gc
         G8gQIOUxOFkAKSDsqOU6+DfvLX9hkupjlTE9zmX9CHkDy0GDIJTIJypQvthvvZ4lbcHs
         VwLob5fcRzee3NJTcSEoqeWED1iqBbK6VWV3Hq/gbVOdQaUovihgnKig2ZNL0FS4D2l8
         lWnkfWNtbx9JwpXOOXwiK780ZDZIx/KyP4DM15hbMCecy2M+FYkQBH5czc7XmH4+yWpn
         G6bg==
X-Gm-Message-State: AOJu0YwDmLfY2CFayFa/5pvgX1dVgonvZ2lJQpDQN73Oma3aGxx6F0/k
	aNaw73zBSpxNxjZmwytqniM=
X-Google-Smtp-Source: AGHT+IEN9d7Y77zaxKBEAafnoreVexmVCnOuHchM36x3agtnhBqqE3jQUhJ5paMLPodITSF5zFVtsg==
X-Received: by 2002:a17:90a:784e:b0:269:4645:80b9 with SMTP id y14-20020a17090a784e00b00269464580b9mr10037249pjl.2.1693929420001;
        Tue, 05 Sep 2023 08:57:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1957:b0:268:5b21:5196 with SMTP id
 nk23-20020a17090b195700b002685b215196ls491424pjb.0.-pod-prod-05-us; Tue, 05
 Sep 2023 08:56:59 -0700 (PDT)
X-Received: by 2002:a17:90a:b109:b0:26b:1081:a432 with SMTP id z9-20020a17090ab10900b0026b1081a432mr9465785pjq.30.1693929419062;
        Tue, 05 Sep 2023 08:56:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693929419; cv=none;
        d=google.com; s=arc-20160816;
        b=oszfqgvoF6V8obKPm5E0Dhrvzbeo3cPXf8AQoGlEJovTASJkusgoFZQuiOFjj9hDOb
         EJm4FzUYFyZUPFS3iL18HIHS30IHzlXQWzvSkRAG5t+26t1/4dMWet/9YYxcjhbB/TaT
         GrcQ+eSsTfqtUkQmRtf5yxr1U66Ezk7aVso71GWw18HBxdQ+rdpRcZqgWfRp1dhoNpRv
         Z02V+QETfIIjjPqKecoT76nTlq6vNCWylp4WhE6b+4Y32qqQ3NLi9T9O0ZYtvPDxcHyj
         wBFPqpeyTerJAXiPo1Q5ZEEz7VFwk75ZKy6JXYiGyFS5zdB5EiPSUt9yJy6PD3caCnCr
         mrbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ThqjLVnbKtocXxKP/wk16gVb0uDcHwyfytUbqO9ZePQ=;
        fh=N3XWbtwaVQKP5OvYRmyh8XEuRlJ1WAqGcqs7JAhSeUk=;
        b=U/JL6Ez+YT1lgOlZ2YAVAIhl5hAkD1sVAFyKzM+m++lFwL2CaYHZaOJOdtae/LKVn1
         O4Hn/d0d1/VyGM1MCvq3PGx6SFqugpLWBKN/QuBjublF+8wEn13gwhsDlqBVw5u0nihS
         bWGohyYNQG9GRagXj9umHO4U0EhFeNJilMnmbI677o9wsHdJI+7lkCZuCf5nru/U175+
         lMT1vNDCcBFLpRLTtCLi4vrau8tIfWSjkqBALSRrb3/M9FzCD4LUaSLn8vYSb3jRlXD9
         aQrHBHxxusKbpDTH6lYBwzwXer6zuWY4FZnDZ7U3F9CcYEwZlYKhlyxelWlnT6mOuuuG
         BhTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=HsZUMGHD;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::32b as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32b.google.com (mail-ot1-x32b.google.com. [2607:f8b0:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id ml1-20020a17090b360100b0026b1cd2537csi761194pjb.1.2023.09.05.08.56.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Sep 2023 08:56:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::32b as permitted sender) client-ip=2607:f8b0:4864:20::32b;
Received: by mail-ot1-x32b.google.com with SMTP id 46e09a7af769-6bca66e6c44so2199307a34.0
        for <kasan-dev@googlegroups.com>; Tue, 05 Sep 2023 08:56:58 -0700 (PDT)
X-Received: by 2002:a9d:66c7:0:b0:6bc:bc3e:f40b with SMTP id
 t7-20020a9d66c7000000b006bcbc3ef40bmr14551486otm.19.1693929418610; Tue, 05
 Sep 2023 08:56:58 -0700 (PDT)
MIME-Version: 1.0
References: <CAKXUXMzR4830pmUfWnwVjGk94inpQ0iz_uXiOnrE2kyV7SUPpg@mail.gmail.com>
 <2023090548-flattery-wrath-8ace@gregkh>
In-Reply-To: <2023090548-flattery-wrath-8ace@gregkh>
From: "'Nick Desaulniers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 5 Sep 2023 08:56:47 -0700
Message-ID: <CAKwvOdnUdfG9=P0gaUxou-xYB24sOzF+HhPrm75EWLETOViuNw@mail.gmail.com>
Subject: Re: Include bac7a1fff792 ("lib/ubsan: remove returns-nonnull-attribute
 checks") into linux-4.14.y
To: Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Lukas Bulwahn <lukas.bulwahn@gmail.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Nathan Chancellor <nathan@kernel.org>, Sasha Levin <sashal@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, llvm@lists.linux.dev, 
	linux- stable <stable@vger.kernel.org>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, eb-gft-team@globallogic.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ndesaulniers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=HsZUMGHD;       spf=pass
 (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::32b
 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Nick Desaulniers <ndesaulniers@google.com>
Reply-To: Nick Desaulniers <ndesaulniers@google.com>
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

On Tue, Sep 5, 2023 at 3:21=E2=80=AFAM Greg Kroah-Hartman
<gregkh@linuxfoundation.org> wrote:
>
> On Tue, Sep 05, 2023 at 12:12:11PM +0200, Lukas Bulwahn wrote:
> > Greg, once checked and confirmed by Andrey or Nick, could you please in=
clude
> > commit bac7a1fff792 ("lib/ubsan: remove returns-nonnull-attribute check=
s") into
> > the linux-4.14.y branch?

Seems fine to me (OK2BACKPORT); I didn't see any follow up fixes to
bac7a1fff792.

>
> Now queued up, thanks.
>
> greg k-h



--=20
Thanks,
~Nick Desaulniers

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAKwvOdnUdfG9%3DP0gaUxou-xYB24sOzF%2BHhPrm75EWLETOViuNw%40mail.gm=
ail.com.

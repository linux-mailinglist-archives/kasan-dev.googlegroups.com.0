Return-Path: <kasan-dev+bncBCCMH5WKTMGRBGOXVD7AKGQE7GCUDTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 804122CEE10
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Dec 2020 13:29:15 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id p6sf3650381pjr.0
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Dec 2020 04:29:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607084954; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q7lyBVqUmRljdH8SsJ32NWS1yMSomITs7mnEF5TUVhvjgy3dyGVnSTmUiACRU752Og
         8SuAYOCpM/rsH7Hpgk1QiDKc7XYcC8ZEcsBSjq1C1T369QI78t/lHJ4d9O1bLxX7DNdd
         QG9EGev3Oe5c504VUSjffGozv80Hy0mGn9fmCTUvMGQm9Hvzolv/P2mJdK7RwGVJNMdA
         6P8kWliraml+bq3FVLjD41CDE4u2G7Sh6OMVA0w0ECEyY15neNas9IwnpYgD22ttNRui
         paWn7GOU5bMmqTKqGPWWFsaMI9tJcOYy8bIMtZD753Bz+M8To2w1jH3fb8NkXB+sRK1y
         JSyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=R+DGrFwf2+NhGpRa5FBn4TePCM73qY/K+fgCdnFp3QQ=;
        b=GcvPSmE/3ySw339NPcMXKOQlrtkn2A9QAprcN9OP07W/nhRoxhBZMAVHSa+sCUqaNT
         D5NmTMaYDcNPKcBz8cbXGUgI2Q0RheamZog+9rfP+0/5UnC5WoYF5MgJtt5yvnzdQ5fB
         qmROcAew2+vDgTVyj5GcfgZCXmjQKM9OWM3jEckDu8PAiwEsuJZ2BBgfLQzN9U/MXILe
         /L7j11pCAizYCO2Y5oDHSTCxg75Hr186xPeaG1V47d63PHXHZ9XwpA0zNRR16oFm1SDL
         ZSruzvNkA0NmA8wkmIa9cr4EmfqzUkiYimGBdOfCPpkZ6xW62MfXQKZShLnuISUspjz/
         LFLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="vQyupD/h";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=R+DGrFwf2+NhGpRa5FBn4TePCM73qY/K+fgCdnFp3QQ=;
        b=M7uAVBz3U24shhKr38IeTm28azynU32kY2EtFiBWjTLSYY1Lf3AJ6XbGAi+plXngEw
         gqN+1XDTZ5zrm8PnsFxuYZRByyb7LBIwnR2r1ntCUO2IAqDsbdRGtbXIZ9tzyqpr0bHS
         K4d7IFnYb9TNgG7ZQbCXtWjRzzvGPXNdLEBETXoi9B908SEunNkVaw4AVTAckpF5TB+/
         MkoBHqzSMXm1e0/7Yu2ypbtAmvZux4yUtZXuGNFFuePNxIMPmnMNzw0d7TWnQ4FMSh5w
         7+IImYEZFRE1Yd4NEEg4ZAMG6etWiBLN4FYsbVdfB0gI3EEZpgrZ+u3DRpJLSG+sDp74
         xR5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=R+DGrFwf2+NhGpRa5FBn4TePCM73qY/K+fgCdnFp3QQ=;
        b=T7QjTW7onHAivM0I6ciaZ1xGigmKJXpDZivjaUMwk8ER8+CrSIazkhMrKn79CC3D5b
         jEB0X6doDBW5u5cypI9O3pg12vIb9mKAhVeFLnqSdplp/ypMGxuQ1xnR+EWLNKwGmgyM
         xSQwj6ytAdO5y4LVGrp/zEPYbNY99OzsTLLSTiGoeEWuxNb3Fi8hjAbSZhEXibWAXAVe
         DtUAncnrSodedPqyUd4e4sHrsl0Ldq2dNvRLQiVJeXmHyUFuF4pYx0jk3ufHY3qixl+P
         L6a/h4Pz4xG9NRBIPFEv33OBW6bVChEUphbuEkmGFNFFRsZQk4ZekmRb0C5a/eHlqqVb
         rxzw==
X-Gm-Message-State: AOAM533aIDLHxX9EGC8MLlBqtuT0Ihogx3dJg8Xw06khRNZUCMC7gYe4
	QzhPasidCv/vZ0t0F1b/Vxg=
X-Google-Smtp-Source: ABdhPJwKISlL3XwQ+CpiH8xJoM27GgdzED68/IqGscY2tssMfOSqsMgEf3nWOZSc6bgyBXuGUPxfVA==
X-Received: by 2002:aa7:9429:0:b029:197:f974:c989 with SMTP id y9-20020aa794290000b0290197f974c989mr3739898pfo.30.1607084954067;
        Fri, 04 Dec 2020 04:29:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8b19:: with SMTP id f25ls1696423pfd.11.gmail; Fri, 04
 Dec 2020 04:29:13 -0800 (PST)
X-Received: by 2002:a63:ee11:: with SMTP id e17mr1399974pgi.436.1607084953495;
        Fri, 04 Dec 2020 04:29:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607084953; cv=none;
        d=google.com; s=arc-20160816;
        b=JEV10Q9Vwn+lDu0RjIvIwIZ8abW6bXHhcjDoxGxXEqE6yzI/etSRzG+vXD57RWUwLM
         Yuinoq4ZRA7v/VFiOHVDmpiTl20fHWVBJDEEefTlJ7yJIF0/K+ev1IWcoJA50ZlKwLSG
         u4Rdo7XJNmt/c8/uVYOi1wuhrg+LK6VrJhM0i2RzHiXkixasvjcEzuFd1DaSDAILB2au
         Ch3UL1orUewetKe0PdmBA2KaXtJSkfYRULNAMIfiyFyrfMfAWv7CR9MJm9ISVYXopJu4
         ROP+nEQoUSw6sQYQV0H0g+mWONaKBFUYhN0cJl3ea/9v0Zgq10KDNI47hsyAqnTfFHeG
         wNxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=E+yzFXIW/SQF93FksrpbqqTewefE+vrapU8Z3tg/OfY=;
        b=BJM8mTZugH08xcUUo9MhdlnYDTdTkk3H8fGP6ce9XOJQ+YF8QkvLoe3w7x5o9XZ6ks
         BT1T0BbFLPq8GcmnSrbWQEbxbE7jZ7gsHnIgDHRGoYFC3yFJgvddIUmYV2NZxCQuLeKj
         ASfJtU4sHnlnlM/tfdMpGjxvftkUgW+qMsDyUnK4jyk+3dRgg6nDzBGQau2kTY6FY84D
         re0OPYK3JBg/NIbd9BymK+TQichTqDHyACsh+hlWf05ciLmv60AxpliTC8XuSeAztpGZ
         rQSm+QGSS9JSE4agz4TTrbjjo/rHuwSwWK1mcLfPnp3vHRNBUDc1zE5Of5LAFripokFp
         Oqhw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="vQyupD/h";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id f14si375544pfe.3.2020.12.04.04.29.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Dec 2020 04:29:13 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id l7so3716465qtp.8
        for <kasan-dev@googlegroups.com>; Fri, 04 Dec 2020 04:29:13 -0800 (PST)
X-Received: by 2002:ac8:4c89:: with SMTP id j9mr8912771qtv.8.1607084952474;
 Fri, 04 Dec 2020 04:29:12 -0800 (PST)
MIME-Version: 1.0
References: <20201204121804.1532849-1-anders.roxell@linaro.org>
In-Reply-To: <20201204121804.1532849-1-anders.roxell@linaro.org>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 4 Dec 2020 13:29:01 +0100
Message-ID: <CAG_fn=VJZC=HfVk_Tx6DUp+M17NZQO4Dao7jrj4WVaQp9jd3=A@mail.gmail.com>
Subject: Re: [PATCH] kfence: fix implicit function declaration
To: Anders Roxell <anders.roxell@linaro.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Marco Elver <elver@google.com>, 
	Dmitriy Vyukov <dvyukov@google.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="vQyupD/h";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::841 as
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

On Fri, Dec 4, 2020 at 1:18 PM Anders Roxell <anders.roxell@linaro.org> wro=
te:
>
> When building kfence the following error shows up:
>
> In file included from mm/kfence/report.c:13:
> arch/arm64/include/asm/kfence.h: In function =E2=80=98kfence_protect_page=
=E2=80=99:
> arch/arm64/include/asm/kfence.h:12:2: error: implicit declaration of func=
tion =E2=80=98set_memory_valid=E2=80=99 [-Werror=3Dimplicit-function-declar=
ation]
>    12 |  set_memory_valid(addr, 1, !protect);
>       |  ^~~~~~~~~~~~~~~~
>
> Use the correct include both
> f2b7c491916d ("set_memory: allow querying whether set_direct_map_*() is a=
ctually enabled")
> and 4c4c75881536 ("arm64, kfence: enable KFENCE for ARM64") went in the
> same day via different trees.
>
> Signed-off-by: Anders Roxell <anders.roxell@linaro.org>
Reviewed-by: Alexander Potapenko <glider@google.com>


Thanks!

> ---
>
> I got this build error in todays next-20201204.
> Andrew, since both patches are in your -mm tree, I think this can be
> folded into 4c4c75881536 ("arm64, kfence: enable KFENCE for ARM64")
>
>  arch/arm64/include/asm/kfence.h | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfe=
nce.h
> index 6c0afeeab635..c44bb368a810 100644
> --- a/arch/arm64/include/asm/kfence.h
> +++ b/arch/arm64/include/asm/kfence.h
> @@ -3,7 +3,7 @@
>  #ifndef __ASM_KFENCE_H
>  #define __ASM_KFENCE_H
>
> -#include <asm/cacheflush.h>
> +#include <asm/set_memory.h>
>
>  static inline bool arch_kfence_init_pool(void) { return true; }
>
> --
> 2.29.2
>


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVJZC%3DHfVk_Tx6DUp%2BM17NZQO4Dao7jrj4WVaQp9jd3%3DA%40mai=
l.gmail.com.

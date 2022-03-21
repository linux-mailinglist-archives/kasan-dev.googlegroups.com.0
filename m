Return-Path: <kasan-dev+bncBCMIZB7QWENRBW5F4KIQMGQEXBJM2RQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id A6A674E2B61
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Mar 2022 15:59:40 +0100 (CET)
Received: by mail-io1-xd3a.google.com with SMTP id h14-20020a05660208ce00b00645c339411bsf10621950ioz.8
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Mar 2022 07:59:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1647874779; cv=pass;
        d=google.com; s=arc-20160816;
        b=C/sAoqHT43FjB+VCbVK+7AU6YF1DD6S4o3sx+uMo42vp/U0ui0o9YY3tX+R0oGpLxT
         gZeMA7yZPlUx/RNAHaJpVjwRuMHHDxohYRZQF8K+8sPH6Qlsr+xhdJrEos556Mam2L29
         MxvcWoOYi3CDrA3FipvxKbKqbqYG2x5qMqzaLG2fTMtAN9/hJ58VTLY+6vPikDXN+75x
         fTY7IZw+XRbqHhsrZwYexOub9Rh2S4sdXxO+yKTFeGWKIpBm2qChhA9NktfaEfyx+2zK
         C6geBXOPv1GTC3NIl/CFhaLFm7B0IWgRogVNt2ByrPzQMsTqKqp7pFBw6Y7tSRsUxUEW
         3Y6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=4ICNuhb9BdjZXymLf8savruvlUOR6y5fTT0PdZ0shIU=;
        b=MnachFUHvuafV6EMAvJtoTSfs+l3waeS3KKE1sZ9mwUmQpGX+d1LCPARARkK7uCNOe
         MY/OgZuYxbfS9YbaZkmaV8KfhEa8VyB/irKkAfZVA6Mzxyd/UfO0ZVz6S5lFt7sWIYFm
         TguK5wyyPT4XynWShJ0Cd0DvdImc2VyLnbgjqxn/D6qnlwg+3TD2Bobh1jtNk5H8oG3O
         hjTAr/d6kTuLFoBzB7Lv9aInfLnd/I8x2Zmi28m4BUnCFW3FQDms/Up/CAkCXbQ/3CQj
         DwiHrmvHdOASTN9w1nXwB29H7pv5ooujwK1i9Woz1VA1XGeDyeRdeaqdSxT3dvtaBphg
         Mxgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=stXTTAi5;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::235 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4ICNuhb9BdjZXymLf8savruvlUOR6y5fTT0PdZ0shIU=;
        b=Z5NraQxl8XJ7A7UoSmBFpB2m5ebBiNa47NjhsIPcEDMbeZDXpR3cloErV6HD9Xa4vX
         u0Q7wssq9NPaect1noUCDAL4FU0wj/7wX261W0A5ghQozNWDvXtDSuWxH+Qf3qV6TVUH
         M9fDOjhHH3W9cUTDXG9fTHznxO8lFiNmsg/wcnKWXtwlQs0H03SZGFomt+SeTm4znfOg
         RVat6J1SWoObW/DHqxJG5wyO5e2MJBprsIyIah+spbsv35tECiv9Mbv1FubjmQBekG7k
         bSL5o5WIxSgQ0tzfDph3KXc/7j67MVGeNABhchhXxWkWuDz2/M32c9fiHyIBo8VGJznf
         SWIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4ICNuhb9BdjZXymLf8savruvlUOR6y5fTT0PdZ0shIU=;
        b=A+0vWXGvnUMEL8Pc7pBxoyQnrLTavSn+w5nQxe0mu665WPoZFYlJERCNucEK/TdlJe
         m9I16ZpxEC1DyzQzJtk57ukzPLaI/k7qxCGhUSzC0LQsnUHCFldfcrLoHPmVAo+vLDq3
         CHG2fhRFQsLmsmMAyzqxZo9JELJ+F8lO1igAxfIvAUJn0lr2nvPp+NiLVEquBQs8oQIv
         yqjl9VIgEjiAHHD/e6puOYHbnpvkbj5A5wImDNJpMjnXpS/sUJbzmnB6656QegSyyQja
         iZ4IniLxdIRyBT++8hJgdf56g4UvmFgUVaHxLD8EehO99e9nE9e2PGk5oVVvR7ytX/1x
         VsJQ==
X-Gm-Message-State: AOAM532VsTKqcagCIYfPl8fLDJjhYfn9nHLq6ogPaSEzVbub/KLIvvj2
	tdwDIE+B+nT4PdrLzRIczLo=
X-Google-Smtp-Source: ABdhPJy6/nCvJoksu9YVVeKWyXFlqIBohEnMi4Q0c/E6N8LmCbo4LtXCVPQIsWmsGWZq9aBiDrBPxw==
X-Received: by 2002:a05:6e02:16c9:b0:2c7:f9ec:5e18 with SMTP id 9-20020a056e0216c900b002c7f9ec5e18mr7696372ilx.317.1647874779451;
        Mon, 21 Mar 2022 07:59:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:1605:b0:31a:7cbb:4918 with SMTP id
 x5-20020a056638160500b0031a7cbb4918ls1839755jas.4.gmail; Mon, 21 Mar 2022
 07:59:39 -0700 (PDT)
X-Received: by 2002:a05:6638:460d:b0:31a:7b70:e1b6 with SMTP id bw13-20020a056638460d00b0031a7b70e1b6mr7184643jab.141.1647874779059;
        Mon, 21 Mar 2022 07:59:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1647874779; cv=none;
        d=google.com; s=arc-20160816;
        b=hUmhbSB1X4MckatpptSgPcOpV3A2xmubOj0UcesbGXK11mUeYWfQOoRJKLeYq6I3/0
         082EddwV6GeiWpJ1kZ2r08Igzy1NrSMvZf34kvPtg1eOWMRxCXy4I4We0uVALTmw8r5z
         jD6VfULdqTkl389TjrEdSyOEcAEyxkzQRBX3PZDunO6YjHYXyeP91gzJB0Lf7hQUKlbu
         XVOpt+YUdrLTIw1PmlSq5Eu+eNYuJCKE4nEQkfnzHxQTgka7fuat8MeWlQmtc6MD26Hj
         r7Md+/9cTRe3C08t6ONDfAa19l2TPrEWVQ+6FpSdNs6197xr3O9j4+Xo9K9qJNLrSTgC
         2TjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OJYydfA3R0CNKR7cdtXJjXTVmaYiDknLd1vXKzC0V/8=;
        b=UZIk4lz6F45iOmb/9TpnwHbjRhRPUpDTcxlpqPTWO5WEHMGv+eVFRcOSvJHqB+nL66
         O7zoz0cg3Yh67xzoFMckRMsgXwPHjsY9KdyafDKUhSl7jcS9H7eP9G2nblxOaqAny1bv
         WSP+EkJQXjX1cNy7CicM1Ml+lBuJJQ0w+wHOowAblrYKZF77h/QcCAGqdt7siY1tl8U9
         7z7Lf/Fz05laEarUiYoEOXN1EFn8Xw3MNbzKnW+/+srJs9n7noB+aueAhrHxLdR1nXBf
         1NWZ9/ZrBNXRetjN7oZ7OWo24xolsjk6mhLa+sxcEPMkliOLdAKi9WxqLqSHFCOmUjm8
         gs7Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=stXTTAi5;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::235 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x235.google.com (mail-oi1-x235.google.com. [2607:f8b0:4864:20::235])
        by gmr-mx.google.com with ESMTPS id x3-20020a023403000000b0031a548f05b8si1067903jae.3.2022.03.21.07.59.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Mar 2022 07:59:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::235 as permitted sender) client-ip=2607:f8b0:4864:20::235;
Received: by mail-oi1-x235.google.com with SMTP id b188so16462285oia.13
        for <kasan-dev@googlegroups.com>; Mon, 21 Mar 2022 07:59:39 -0700 (PDT)
X-Received: by 2002:a54:4899:0:b0:2ef:3d97:2528 with SMTP id
 r25-20020a544899000000b002ef3d972528mr6394134oic.211.1647874778496; Mon, 21
 Mar 2022 07:59:38 -0700 (PDT)
MIME-Version: 1.0
References: <20220314090652.1607915-1-dvyukov@google.com>
In-Reply-To: <20220314090652.1607915-1-dvyukov@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 21 Mar 2022 15:59:27 +0100
Message-ID: <CACT4Y+YA4eFJUe1Ozh--YBMfxZ-ByiMmg0qs6En+wV2-JhQ9-A@mail.gmail.com>
Subject: Re: [PATCH] riscv: Increase stack size under KASAN
To: paul.walmsley@sifive.com, palmer@dabbelt.com, aou@eecs.berkeley.edu, 
	alexandre.ghiti@canonical.com
Cc: syzbot+0600986d88e2d4d7ebb8@syzkaller.appspotmail.com, 
	linux-riscv@lists.infradead.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=stXTTAi5;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::235
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Mon, 14 Mar 2022 at 10:06, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> KASAN requires more stack space because of compiler instrumentation.
> Increase stack size as other arches do.
>
> Signed-off-by: Dmitry Vyukov <dvyukov@google.com>
> Reported-by: syzbot+0600986d88e2d4d7ebb8@syzkaller.appspotmail.com
> Cc: linux-riscv@lists.infradead.org
> Cc: kasan-dev@googlegroups.com

ping

> ---
>  arch/riscv/include/asm/thread_info.h | 10 ++++++++--
>  1 file changed, 8 insertions(+), 2 deletions(-)
>
> diff --git a/arch/riscv/include/asm/thread_info.h b/arch/riscv/include/asm/thread_info.h
> index 60da0dcacf145..74d888c8d631a 100644
> --- a/arch/riscv/include/asm/thread_info.h
> +++ b/arch/riscv/include/asm/thread_info.h
> @@ -11,11 +11,17 @@
>  #include <asm/page.h>
>  #include <linux/const.h>
>
> +#ifdef CONFIG_KASAN
> +#define KASAN_STACK_ORDER 1
> +#else
> +#define KASAN_STACK_ORDER 0
> +#endif
> +
>  /* thread information allocation */
>  #ifdef CONFIG_64BIT
> -#define THREAD_SIZE_ORDER      (2)
> +#define THREAD_SIZE_ORDER      (2 + KASAN_STACK_ORDER)
>  #else
> -#define THREAD_SIZE_ORDER      (1)
> +#define THREAD_SIZE_ORDER      (1 + KASAN_STACK_ORDER)
>  #endif
>  #define THREAD_SIZE            (PAGE_SIZE << THREAD_SIZE_ORDER)
>
>
> base-commit: 0966d385830de3470b7131db8e86c0c5bc9c52dc
> --
> 2.35.1.723.g4982287a31-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYA4eFJUe1Ozh--YBMfxZ-ByiMmg0qs6En%2BwV2-JhQ9-A%40mail.gmail.com.

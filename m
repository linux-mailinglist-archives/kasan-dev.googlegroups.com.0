Return-Path: <kasan-dev+bncBDW2JDUY5AORBY5RU7BAMGQEV7GUI4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8BEB8AD5F14
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Jun 2025 21:28:36 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-3a4eb6fcd88sf144737f8f.1
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Jun 2025 12:28:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1749670116; cv=pass;
        d=google.com; s=arc-20240605;
        b=h8YRtuVTKBTev2Do2TakLV2wDpPrh2BdEpQO9cRqY5/cvWl9i0ItNlFolOOp5iRC3c
         s4Ivu8LVyV2avMTdiUM/iNjGT4mNOq7zCn8B42Ne82SA0SdQLuI6DsLpW3UqJbYkQVx3
         s45Ya3FFIKOpjJ3NySJSJ64f1uukQGbRQ+3WL1Rf7nf2BRdFDZE/ea7ZBDCC3f85Tg6c
         Mm/0sjZgcuATgmzmjZG1Z7fxOi9Ur5fLp9YgiBNWBU1+Yjks+htQ+9SS5MSdsevoQePb
         SeIx1B+Y+PwfEG7VRklzgE8TIiNMWEOfUw/OinR+81SwJLMeSsfH1OixidhR1krfwPrd
         hqYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=qtdSgkhG4zOE1I9VcaNxcEFFyDk40DK6oeukzZwfjeI=;
        fh=H2EkLRea1yULu4yfHVz14p3OLB9oWv0g/mfBweaac8E=;
        b=QEk7uw4Wq1xIA73iV0N8Vfg6eJUN8BOa2otwtW75NCPhzS9y0fJRUSFqCK+v3+j/lP
         aQRH0dS21GUKXEHeIgnEkwkQE+OITfbqdpUGjO0/oIjuqLNrhYidAtt2DaZdpXnCmszu
         aJ91vTvS4IVik43Rb9/rhsk/GO0/PRGllhmrWpbU8hEwpbEVCpixABkETOA+jFQoE5gj
         4fN4PygQD7RLTb0iFz+O7eS6CIANCw++ltTubLiQLo7c/VuykKO5UALBRiYOsxNEzGqe
         dqBoHlkXrZL1QmRkijPWpX1jnxU7y5Ww2lTgYUQXRhMymZu7RH9Qv10Rn6D2n2gE970V
         u2Kg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=flaKEJw3;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1749670116; x=1750274916; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=qtdSgkhG4zOE1I9VcaNxcEFFyDk40DK6oeukzZwfjeI=;
        b=ESWy1Y4s8BjFa2PFoEH/f8TUbr6Vb3rDr3HtwGD0OFITGd2yE9T8VahEEvRG9RvcLV
         h77xy2q5e/hebdxkZWa0aWUBegbKjQMEujSVhWjObnEq1FIatX46vezsHv29Zj4v6Jh2
         SjgGcz6qc06Ss2GsNFeqv1PjElx4UiwqstvDKkSugos83L3WhtED5YD1bYYtQkEyt06Y
         Xl59O0qnbPOTPZgYo2Li9XMmjy7dPwR7ByfVDwHpEwQME+jHcZlP3fy4KjBf+bweZGiA
         XpQyOS0QvmBO9iUV9oaiCfPdRuh48fnkNknEdhjtpjxIsBPuPaFx8k580l4eiPAzeDNZ
         jYsw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1749670116; x=1750274916; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qtdSgkhG4zOE1I9VcaNxcEFFyDk40DK6oeukzZwfjeI=;
        b=gIQIj6UVQCt5eVx0fvBbH8IGQ1mFexQf5GiWAxehCLJESnKcI1PvZW0UWdtrWgIcZW
         5L28wNTFPUOeOw0iUh/dPiWSXbmqgQqL7YoeXK+9GY/rgl5tdrVdF7Hw35CqXoIKXDin
         IFHfEzXyLG64/qFRmMgvgbEyL6AttzpVpgN8fpFZQL+qqZe0iojaHoQ3htrKMqS9aJev
         XTNbGFwUr/1eAcIonNF+MtBzsA87gtes/0vt7hOGZPOf9Z4Dd5Q1GRYnnWJ58ji8yn5D
         1pcxKDffm3R6pEyCxqvUxVYWhxte09QQ3afRukCmxBGBYXQcebnkdv0NCFtp1Jykj5XO
         W9zw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1749670116; x=1750274916;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=qtdSgkhG4zOE1I9VcaNxcEFFyDk40DK6oeukzZwfjeI=;
        b=DZuI4Z2qH/hiYQ4ef8X1JaozTkyTOgcMQ7cSp0/5QubOFJcncuobU/E7ayCWSimiTA
         sgSU1J8cKbewuWpPVz7xMYBEXk/NKM03tHKVetf4549zZw+0/c1LK7wlelAb9p9bxRTp
         LOMEGPDhSm+l4hA57IHBV5/Wh0v03HI7mkNhZdkDv9zjncEPW1pjrBuoYEDss6ymARge
         +dqDDuN3mvloc5DvHLj9ZQh7D2JJL2EKC7eHTWbpV+HWCFbdnQP7GX869gn62/7UfW/3
         /JWNcaGJZ77vLu4dFG9OzgO/fohm4DHN4poilU71j5uGNLscB0i5FTjeobUP8/P7by1t
         X/Ww==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWhDB/cIntSdhLgmR8JES4HWm5COp07GvvOrmrXCDFxzh9Q3qrG28M69FJDFjfew5h9iZHMxQ==@lfdr.de
X-Gm-Message-State: AOJu0Yxs/0nnAN6xAYJYpq90YrPurX7JRz2tNlj59dn0gcuPorWh5QUG
	/ZyZ/OLsiUJlgw4Ed7vZH43pvGqgJ1J1PjXmuCK0bFtvYXgnuO1kf0X1
X-Google-Smtp-Source: AGHT+IHNbnotrFFday2NUqLEqtpuG9bl9gW3wShfYIV8Ynw7TW6sEV3hi+IePBnBZXkjEwGr5bNeZQ==
X-Received: by 2002:a05:6000:2dc4:b0:3a5:5103:6ff2 with SMTP id ffacd0b85a97d-3a5614a48b9mr119307f8f.28.1749670115511;
        Wed, 11 Jun 2025 12:28:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcBqOBdivgP3GVdfhHCz1+q67tE0aKdrc4cF94XD6Xp4g==
Received: by 2002:a05:6000:188b:b0:3a4:eed9:752e with SMTP id
 ffacd0b85a97d-3a560184fe1ls92996f8f.1.-pod-prod-07-eu; Wed, 11 Jun 2025
 12:28:33 -0700 (PDT)
X-Received: by 2002:a05:6000:24c8:b0:3a4:ef36:1f4d with SMTP id ffacd0b85a97d-3a5614ac453mr114297f8f.38.1749670113238;
        Wed, 11 Jun 2025 12:28:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1749670113; cv=none;
        d=google.com; s=arc-20240605;
        b=lKwuryM9WUvB1CtTUAmD4Iz4j965CJj//1r8qKib1bCQvi3b71o7OM2s/fq0nnZReL
         IwnRGROrAfVFrRizHSrC2f8n0xqm5JAqk1gbCQ6eCseQPJxVQMVmWxTGj0/4g8XWbBIN
         MzO4foBxzkFrEuQj+xTr68qWf7Zy3r6QNCdqPOrEfLuoiwh2HNGp4moqNAjaYljZvIls
         mx3xeY97R0135FjwN27FgRD6gUnbwquwkg7ArTHI36fLszTgT6Cj+qjuPjgLk/Y15N1c
         GRH5sDOndZR9al+NVNb7LYZ0VIIBpRkzXcX/Ujgz+9zD3CvkIeArKeRS0y3MqfhcBhU/
         2VYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=cRn0/RikhaLQpqrkCQkGtEPcmqAdXo3lGmoVtPHDXbo=;
        fh=2lsUIz+BICPKGoruVn5PQ6eMV1TqeJjGPhknO964m/Q=;
        b=fK0V9pXBvMSEZ4zRKCf5DetA7k8KnbnjOyrI2/isWyHoeAy8ItTfzkVMarCscvWeJa
         dKyPoRlsmo44sT+sMMrlVgtve0KKMcfTZZL3VtGQO+WRHJKE+7yBTOTvOh7oEu5e67P3
         czwtE7oTselj3tfbQUZtRVlrsZSdT2yTW4PjFIw1QgKiKwJmqs2uiTSDdCTmlMNcdecx
         dXsMZ8ygFMf96V27wKJMS0JXAAAa9rKXjLkeYysRiZEUEH7qZh7BleC/N7xZ99mkFHtA
         Fyq9YgSAb3o/5qoiFhtxiFQo3K/TjxMayk1QXgfqd6gtcmMLWhhC6DuihbNeS/WsQKwv
         Lb5Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=flaKEJw3;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x434.google.com (mail-wr1-x434.google.com. [2a00:1450:4864:20::434])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3a532294e86si280409f8f.2.2025.06.11.12.28.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Jun 2025 12:28:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::434 as permitted sender) client-ip=2a00:1450:4864:20::434;
Received: by mail-wr1-x434.google.com with SMTP id ffacd0b85a97d-3a54690d369so228977f8f.3
        for <kasan-dev@googlegroups.com>; Wed, 11 Jun 2025 12:28:33 -0700 (PDT)
X-Gm-Gg: ASbGncu6joIll3VVQsWlk/hnHL0HlOvI9tL5EZwix7zK5snhQ1yi4M0Janffwptk6Vp
	X6ecHl7PZtc6wB+g2oILVxmpTM0ytP06a6LdKlYBSh6qtsP1xwzEfwaeronlaJwfQIwwC0eWDp/
	TY//8nSWIu0OGeZUUWw+3rOSLvaKtOAq0jmKmHpVcdw/6y6/Z004qkTOsx
X-Received: by 2002:a05:6000:250f:b0:3a4:fbd9:58e6 with SMTP id
 ffacd0b85a97d-3a5614dbab3mr118857f8f.50.1749670112564; Wed, 11 Jun 2025
 12:28:32 -0700 (PDT)
MIME-Version: 1.0
References: <cwl647kdiutqnfxx7o2ii3c2ox5pe2pmcnznuc5d4oupyhw5sz@bfmpoc742awm>
 <CA+fCnZeUysBf6JU8fAtT8JXd7UhgdWtk6VBvX+b3L3WmV4tyMg@mail.gmail.com> <mdzu3yp4jodhorwzz2lxxkg435nuwqmuv6l45hcex7ke6pa3wv@zj5awxiiiack>
In-Reply-To: <mdzu3yp4jodhorwzz2lxxkg435nuwqmuv6l45hcex7ke6pa3wv@zj5awxiiiack>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 11 Jun 2025 21:28:20 +0200
X-Gm-Features: AX0GCFuPlPgYPMpjxvFYkUzam96eSNxWhV3TuZo4mKxJ_ax9vVo0lM-miuhV4hw
Message-ID: <CA+fCnZfSJKS3hr6+FTnHfhH32DYPrcAgfvxDZrzbz900Gm20jA@mail.gmail.com>
Subject: Re: KASAN stack and inline
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=flaKEJw3;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::434
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Wed, Jun 11, 2025 at 8:22=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> >
> >You can try disabling the instrumentation of the function that causes
> >the issue via the __no_sanitize_address annotation if see if that
> >helps, and then debug based on that.
>
> I already tried all the sanitization disabling tricks. In the end it turn=
ed out
> that a compiler parameter is missing for x86 SW_TAGS. This one to be spec=
ific:
>
>         hwasan-experimental-use-page-aliases=3D$(stack_enable)

Ah, didn't know about this parameter.

Looking at the code, I actually don't understand what it supposed to contro=
l.

It seems that if hwasan-experimental-use-page-aliases is enabled, then
stack instrumentation just gets disabled? Is this what we want?

>
> Looking at LLVM code it must have disabled only some functionality of the=
 stack
> instrumentation and therefore it gave me some odd issues.
>
> Anyway I'll add this parameter to my series since with that it looks like=
 it's
> working. I'll also have to recheck every possible inline/outline/stack/no=
-stack
> combination :b

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZfSJKS3hr6%2BFTnHfhH32DYPrcAgfvxDZrzbz900Gm20jA%40mail.gmail.com.

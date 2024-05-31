Return-Path: <kasan-dev+bncBC7OD3FKWUERBB6I4SZAMGQEBLR6MSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 189838D57A5
	for <lists+kasan-dev@lfdr.de>; Fri, 31 May 2024 03:12:41 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-43fcc0c6fdfsf17717231cf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 30 May 2024 18:12:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1717117960; cv=pass;
        d=google.com; s=arc-20160816;
        b=i/hYazS9PCGEDDbCSQEPDVrv0u6l6lTrJ3h3PPKGcye9WB6I3ObGjNVBzOYx6/G9bd
         UOFuR9xiTjYGaPTm06WkGd4uJ+sF/Lj5cmk+IcPPIgMg+WlNkOy9u/hcuX3kVQsg3+PO
         wgkUD+RbZl8onw4VXBR0bmuBQgA2E3fGIBhsqVCHNsbBNobF3+D4Q1Nb8QjD9fw/ZCs7
         pNSnZUUv18PxX0kkuCKd53+LWQRynLFCP/La53MgSx/VxMJnVDII8d9umlAMFx2crcse
         c72mxRN7Nk62yUlM2C/00QiiPTuNzCsVH7K48wC7Rny5rml6rm/jUVERIAIXOCB3Pfuk
         NEPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FKMrx/KlHqG3otUM+Jjj3UaSuij+EiUIxcG0jrY1xK8=;
        fh=wJziwPDMZV/eMVegYmCrCH6ciqevnu+TgqjenC/FerE=;
        b=OnwweVy7bQlq8SpUquavi1ijBEUPuKhRkhUfjtFpkJcDX4wjkAK+rKEqBIO5g0FpdC
         bPDcsRua+qPTDR9/DVHi2Bml820sJYgowdr7UKxrdhReNxh9OhOMBnOisbzJdTkpRYdo
         27lPEbRuPFIPUpsGWgPGBk1mLv+isLT6V89GdzMFo50Yl4sqPAMeQUKMUhF5HDJVWyue
         aYxBikq5KWo4YaCvDKM9Gj4Sb8dkAF54it7twp4YVC6KGKuzjcSYA8VhAAlVsEndaGeR
         L13XQae4wMsqpfCvorH77G58LhYtBbN/591cIDaT0Lm29j+wXLNq53HcVdUd4qB+Ggfz
         I2Lw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="aNH/0/ua";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1717117960; x=1717722760; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=FKMrx/KlHqG3otUM+Jjj3UaSuij+EiUIxcG0jrY1xK8=;
        b=GxDOZvWwl6T227+XndeBHp74kzXAiNLOE3FxA/pwz7fIKNfgJkzc7QqAwRzvx1BYvx
         wO8LBJwq/sToSuecti4Sk49Dw+W7N/O3eJlBde28zE6dvKriOs8Bs8OY9q4r0draamKx
         Stlf1w9HGy3znmlRluhJgKGWlWXW4M1ca5OUSbZaviuybSCIRGHz+msVutu4UCRfVQkK
         AUuAE+hoY5BxFm8wxHwGD3z7v0rduTql83sBbmOaq31jKBxCY7si+DXS8eNFqGN0LHKK
         MrYMgm4R4HDHlxT2MX+8Tg34Q0yUYjgCdlGxdQGLAL0G2ACEjBiUMJ4hEZtipdBrvHz1
         VkLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1717117960; x=1717722760;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=FKMrx/KlHqG3otUM+Jjj3UaSuij+EiUIxcG0jrY1xK8=;
        b=Y6554zbvOug4SX24e6J97sY8d0Ph5ha6mj8wz9QybbE1OAgdu16ejLAqIIbVCXb8QH
         vzTBKuuet31Izh5acf/Rf8hHJUtE5YeVpGf+ztbl4s8Mj60hP6nIkaXXiNVk/PTIC5gM
         ke41jr7IKH1rKAOkauWfGa5ftOYoatnLUivfbCZlgIW6cjZqrxEMGQYBsuvMCTOh+9Pr
         bjW1ljW+FrcPo4IHhoGDtL8Yz5bGbl2tvs9jnE2STFHqA08PHpBsI3XGLyZ+LHFRPQ/p
         s85UjqAoJz/YY7zqi6zarpcXee5yK63Q166yPgId+x9JuhCB3HPo0WPmuNEJt0T/0VIK
         xHow==
X-Forwarded-Encrypted: i=2; AJvYcCXPp4XqE3iSh9qQ//LY1aBx/1PGCEhsX5RtjDNMK/z4ehybbsJ5L2GKVvGXZIPdYVJ4xhIhatgVu8W4cc4TzwC2696Ui6KNXw==
X-Gm-Message-State: AOJu0YwL6oVw0NNwqbD9VQbi+1J7r3w3Xnpt9lWvjDLwheTcAU/LN9Rm
	R2ojNqDwoJq1qtoU0zgVL9suS9LtjJYM42TU8Wg5D5Qlf6ZKdsEr
X-Google-Smtp-Source: AGHT+IGZWirmv8qzbLJYBHWjNxZQHWB3eoHnrmRxTl/BWIgZCTYWX6MlCNRCKbgt0W2UfLzf7ryUHg==
X-Received: by 2002:ac8:5f46:0:b0:43f:b829:cf13 with SMTP id d75a77b69052e-43ff5272b49mr5110151cf.31.1717117959662;
        Thu, 30 May 2024 18:12:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7e89:0:b0:43a:d7f2:514f with SMTP id d75a77b69052e-43fe915c12fls11823281cf.1.-pod-prod-08-us;
 Thu, 30 May 2024 18:12:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWpijg3NBmcUF555E4Ws8vgXiz9dNNVj+Lfhlo72HcswX1NJKZnxQRJ5od/lFJWCG2UKBHSsI7Re7DWUvvqtfyTkjJXat8qA3w2lg==
X-Received: by 2002:ac8:5707:0:b0:43a:f697:667f with SMTP id d75a77b69052e-43ff54b02dbmr5085661cf.48.1717117958887;
        Thu, 30 May 2024 18:12:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1717117958; cv=none;
        d=google.com; s=arc-20160816;
        b=tt6DbAX6+mj/CSEP8p8i/FvGl6E05F1Ya+oLFGub3NDL8vhPW4hr+tkI4oC3UB7JVN
         oM7NjFWZp4kCJ4chsB3kLMaYApBZiFL218H1WT55n38J3KqcxqztFXGCtlqnEpkgukS+
         HgUh/9I+ZlwBNbziSohN+CKZJV7pvtofGP+twZNly/t0y9AQZp9yZRDCor2WMLnDNWR8
         Cmn0f/kIV/WcnAozNiKn2ZsMLTnrjmLQG+/VWop9OK2UdajOgf1d/d63wyHfydDfqXCO
         +Tl9LdzbUtGZnK8VT/2/18o/v3dG1ZD2kyFNsNx1kUXv+4WmtXSsw5VEYJALNZkyZC62
         mgxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=jMNqn+VzgJDh1HW7KbXMrJ/PRgsITmUpxO+rT9xOuHw=;
        fh=d7bHFJE0cbUgG+mCdHCri3Q9t4b6BClEFLRM40uCLJE=;
        b=VBgyY+J3qFe+pLR7FjbwcfEJ8foz4nzNKYQLpB8PQj/A1cdCw24quw4LH0ZJ9l20mk
         /ObPufDcGSX3qoy/h4yqPW2Kzg6N67IDRmzG3RXYW/VJvvmZ1/2jv26qk9yPW9kalY17
         ug5uhOyuUD/E8h9B3O9VpNube3RJlbwneSZqriz4a07l0Xu3UcgM8cX0/1yhDRZ8q2cq
         QjPik/FxB1h61cly21rvOYjQxI3VN1m86U486xknMZjMGRijD0BJcU5JnfTRdE6Blx5s
         K916epIe3yclqrrCU38PYYji32y3B6vW6CgtDZcpqLLLzrJaV+8uelPx7zVFq/ny5ptd
         Oiew==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="aNH/0/ua";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2c.google.com (mail-yb1-xb2c.google.com. [2607:f8b0:4864:20::b2c])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-43ff25b6ddbsi585601cf.5.2024.05.30.18.12.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 May 2024 18:12:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as permitted sender) client-ip=2607:f8b0:4864:20::b2c;
Received: by mail-yb1-xb2c.google.com with SMTP id 3f1490d57ef6-dfa629b4e0eso1164276276.2
        for <kasan-dev@googlegroups.com>; Thu, 30 May 2024 18:12:38 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWCnNOQtfSiPZLBI1YdBJjXGcevFzpV8W4NQbuyXgu5x+GWXvWocXbTkisVltnOHk7CIFFpbFshEXA7FkGK5qB4CnA1tB5ei5B8Hw==
X-Received: by 2002:a25:ad65:0:b0:dfa:7233:4942 with SMTP id
 3f1490d57ef6-dfa73bc2869mr586621276.6.1717117958213; Thu, 30 May 2024
 18:12:38 -0700 (PDT)
MIME-Version: 1.0
References: <Zlj0CNam_zIuJuB6@bombadil.infradead.org> <fkotssj75qj5g5kosjgsewitoiyyqztj2hlxfmgwmwn6pxjhpl@ps57kalkeeqp>
 <ZlkICDI7djlmpYpr@bombadil.infradead.org>
In-Reply-To: <ZlkICDI7djlmpYpr@bombadil.infradead.org>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 30 May 2024 18:12:24 -0700
Message-ID: <CAJuCfpEz+-VeE0-6Z1ks7BTLGmC7JOsM9bHKN5jMqgn9rutmAg@mail.gmail.com>
Subject: Re: allocation tagging splats xfs generic/531
To: Luis Chamberlain <mcgrof@kernel.org>
Cc: Kent Overstreet <kent.overstreet@linux.dev>, linux-xfs@vger.kernel.org, 
	linux-mm@kvack.org, david@fromorbit.com, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	kdevops@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="aNH/0/ua";       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2c as
 permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Thu, May 30, 2024 at 4:13=E2=80=AFPM Luis Chamberlain <mcgrof@kernel.org=
> wrote:
>
> On Thu, May 30, 2024 at 07:03:47PM -0400, Kent Overstreet wrote:
> > this only pops with kasan enabled, so kasan is doing something weird

Thanks for taking a look. I'm back from vacation and will try to dig
up the root cause.

>
> Ok thanks, but it means I gotta disable either mem profiling or kasan. An=
d
> since this is to see what other kernel configs to enable or disable
> to help debug fstests better on kdevops too, kasan seems to win, and
> I suspect I can't be the only other user who might end up concluding the
> same.

To avoid the warning you could disable
CONFIG_MEM_ALLOC_PROFILING_DEBUG until this issue is fixed. This
should allow you to use mem profiling together with kasan.
Thanks,
Suren.

>
> This is easily redproducible by just *boot* on kdevops if you enable
> KASAN and memprofiling today. generic/531 was just another example. So
> hopefully kasan folks have enough info for folks interested to help
> chase it down.
>
>   Luis

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpEz%2B-VeE0-6Z1ks7BTLGmC7JOsM9bHKN5jMqgn9rutmAg%40mail.gmai=
l.com.

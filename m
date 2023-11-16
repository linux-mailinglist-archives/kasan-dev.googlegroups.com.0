Return-Path: <kasan-dev+bncBCCMH5WKTMGRBXO63CVAMGQEALQUJFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id AAAD17EE3D5
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 16:03:58 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-35ab1490a70sf8944555ab.0
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 07:03:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700147037; cv=pass;
        d=google.com; s=arc-20160816;
        b=G4d8x7wOF1qEYp8CsASlI0eOH/W8Kntnd0NFhrXcFHJaz7H5YcM68ghYhkMLqIQeNl
         i14NaZMvig4rZmnP9djLFXTYvKhBCptC6m0oR2pTtIcI3mx9VP0aqG8Cxwz3eWp403mO
         VzV0utiip70vPbbJfYuy1sjguL4+6xfNo4CX3lc2f3br+HUVYFECX2p8X7XR0QcEjV2Z
         WVL4yDwJsncstkTsrdQUD8ncHrUyD80huQ6rEKeqOhmackTRd+oZKyjRlMO7OAzTStmA
         +lqycHnzS9+JWRRtjmgcM529Zig151xPa2KeRJyuV2UMVlX0K+kLo4urIAqlirvxnTQ4
         jTdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hzLR/3E8KYsJVei+6hZ8VO6Dgtp5QkBh5rxs6iT3Cts=;
        fh=YZa8vkdUz4pzRj6QFVU/SyYW+LsIH/Wz0o5e5dUhKFo=;
        b=mrp5uspaSrez2vLocVtdkVdL44/iBo9L8mGZILy4ChiMfiu+xLo0vqTlWVn6pZ3fDK
         PHR9gdhtM9YeGjkBSPWMIIY81GdvaMsiKQnXs0Yf0jUS+kJzUj7+QvkYMA9N5aMJ6BuM
         TV99TFHrNVAyvcH8zO1u//sK+E0O2y1cXECKOZgiJvfYZ2dpjIm0mQoE9P4gDGMyY6Km
         itZkzZAl3+fhkIrwRsyRD6y7Yg4K0PhHnJL7SSaMd7XtEpcyN5+a5dmwM0sepx8lZb42
         AwrU/bdUCdRyUK0i2ie6ATzcleSZ6zKo7QIhq/EwuBLvSWdvKsNN/foPf/Rga+nksTLA
         z1QQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nLFTpzVI;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700147037; x=1700751837; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=hzLR/3E8KYsJVei+6hZ8VO6Dgtp5QkBh5rxs6iT3Cts=;
        b=sWNnWupj30uW09bB/0DXUEOWnCXIqNNm/pE4wH6M/d5kCkH/Qk867ZUrXK5UgnNM/5
         SWizIhLkNIop5KHT7n//Q7ftMVp3JM8JOrsMaI+TfS2RlhXOYzgZRbfFZaDZrwJ6sJQs
         UtKNOqmmuetGMmL7sJ/bl4UiVJCc0jsy0+S9vp7LK60sLv2Rak9M9DY/VaAhVWbb0JL4
         a208v81NAHPFIHzaBfk5sw9lgKNkjPCzpBLm7ABgP9zmr0draqHmExyyQ2dgFuS5GDu6
         bqVhH012nMbiQRW0h7g+pvplGcJ1RhXAjekdWT3FgkEN0LWLhh4OU2TohUXYmQuW+z12
         pyzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700147037; x=1700751837;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=hzLR/3E8KYsJVei+6hZ8VO6Dgtp5QkBh5rxs6iT3Cts=;
        b=mQMpxULL9ULMeQnzbAFjF37dgg2DLitZcdJHh3ak5Ld1uplj0tC/Q2Nfhp1Epa2Lh2
         3wS4wol8qCxo50s+G3fuNlaHLngd1uThxEpxoivswSYaTSwpEr2pAIrVeDMLNA9wRcIC
         DeMh8MzmJiG1mx2xcevUePwMBRE4UzVZTnU3NnZecaZLRoHivvCnsNVuJ8k89ag9f8mk
         7q7fJhzaf1hTWRj4y+jZ0YCDxvASPhC6G18/l4qKkiTGfa0ZbZ/sybuAfMyJOMym/jqL
         fdpPZM6wMWgjqj/nXZTJcPzdsKwVG6gpk2q1VNCblq9uJ6ak8+QY3RSB4N0Rk+9hv4R4
         gaDw==
X-Gm-Message-State: AOJu0Yxf/uw1iM7nl1+nFMKiMrrAhQsR7irLkEdRKI2pX8ElwfDnz6mY
	wGC9ghBO6CHTDB5HzUB0zeg=
X-Google-Smtp-Source: AGHT+IFJsSiEm9NMqh3Jd/NPCnDpzQ3Khf7vBPCS6Wh1pAb/+lp3eQWBfe49YA/kxHdDWFERqzaJJw==
X-Received: by 2002:a05:6e02:1a23:b0:359:4c9a:9a93 with SMTP id g3-20020a056e021a2300b003594c9a9a93mr20236737ile.31.1700147037435;
        Thu, 16 Nov 2023 07:03:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c00f:0:b0:359:48ed:fac7 with SMTP id q15-20020a92c00f000000b0035948edfac7ls581226ild.1.-pod-prod-08-us;
 Thu, 16 Nov 2023 07:03:56 -0800 (PST)
X-Received: by 2002:a05:6e02:158b:b0:359:cc3e:cad with SMTP id m11-20020a056e02158b00b00359cc3e0cadmr21292373ilu.5.1700147035353;
        Thu, 16 Nov 2023 07:03:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700147035; cv=none;
        d=google.com; s=arc-20160816;
        b=c/nlU1+z7NfPXOxs49InCpuHKu7dzEKlAm4Hv1v/D9NVbVv14K6K+h3VParWkd6Gxx
         4VHz+O7PRjFJ5nA9cZ2t41VgSA/X2WcHKolqZnOU5ewalxbPN22uJ3tXo2xhrwdOoLHx
         a5Z49FHzy9equ69ZB1E9icQN7LL32S5c3FYzGhnTlR/zc6DwL82Pf2WuMGip0r3B04rn
         G28qkBbHog56zBpFdod6jjiVfH3c9QTcADi7HlcO0S1rGCu/g5Jc42KpO42oNtX+IvKc
         5girwWI/+0hGaAW/gJ1OPrmWLGG7vLirlJfcnx7BYXD4BsVw39lXCgenZWZZpRBO4uox
         /RuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=BEPBtVIehZENietqQgMRaLfueUPVKPaQSiz0lKmUCO4=;
        fh=YZa8vkdUz4pzRj6QFVU/SyYW+LsIH/Wz0o5e5dUhKFo=;
        b=AhGlTdPbvlol+waOSAlH3hYfH+udZzVKxbXlVSXNFwaw1SKvFJdck/9wZH6sPgKtRz
         g4YofdBn+WlBwV/dKpvohsHXomfm37H+Kw9SX09zeo09xwRFIqjoodHqyDQl7UF47lxp
         aKoFKof9wYW7vvDyUPAHzhasXceEmSpKdBUM0owYXWISfMB+DA4fyvyou2/UzH8jElWs
         n2gbRXdw8Q1jWLg4iXiqXN6AtPHeWcJbRilPVL2OSc3vYGZZ6MaMv8kplmDyf+aBnzVX
         L9X1T8Ej+OpVXFxhl3VPIAAwAL8/LhaidfOY3LwuegpVh2lPv/wyIoIN7MgtydonSkU+
         kpNA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nLFTpzVI;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf29.google.com (mail-qv1-xf29.google.com. [2607:f8b0:4864:20::f29])
        by gmr-mx.google.com with ESMTPS id bp13-20020a056e02348d00b0035ab283d159si1424739ilb.1.2023.11.16.07.03.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Nov 2023 07:03:55 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) client-ip=2607:f8b0:4864:20::f29;
Received: by mail-qv1-xf29.google.com with SMTP id 6a1803df08f44-66cfd35f595so4836166d6.2
        for <kasan-dev@googlegroups.com>; Thu, 16 Nov 2023 07:03:55 -0800 (PST)
X-Received: by 2002:ad4:4b6f:0:b0:66d:55d9:bc7b with SMTP id
 m15-20020ad44b6f000000b0066d55d9bc7bmr8646936qvx.31.1700147034569; Thu, 16
 Nov 2023 07:03:54 -0800 (PST)
MIME-Version: 1.0
References: <20231115203401.2495875-1-iii@linux.ibm.com> <20231115203401.2495875-27-iii@linux.ibm.com>
In-Reply-To: <20231115203401.2495875-27-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Nov 2023 16:03:13 +0100
Message-ID: <CAG_fn=XSKh=AmU3mEC7dNmEFk5LaLt+y+TfsVcD0Dn5NsbTBSw@mail.gmail.com>
Subject: Re: [PATCH 26/32] s390/mm: Define KMSAN metadata for vmalloc and modules
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Marco Elver <elver@google.com>, Masami Hiramatsu <mhiramat@kernel.org>, 
	Pekka Enberg <penberg@kernel.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Christian Borntraeger <borntraeger@linux.ibm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=nLFTpzVI;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as
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

On Wed, Nov 15, 2023 at 9:35=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.com=
> wrote:
>
> The pages for the KMSAN metadata associated with most kernel mappings
> are taken from memblock by the common code. However, vmalloc and module
> metadata needs to be defined by the architectures.
>
> Be a little bit more careful than x86: allocate exactly MODULES_LEN
> for the module shadow and origins, and then take 2/3 of vmalloc for
> the vmalloc shadow and origins. This ensures that users passing small
> vmalloc=3D values on the command line do not cause module metadata
> collisions.
>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
> ---
>  arch/s390/boot/startup.c        |  8 ++++++++
>  arch/s390/include/asm/pgtable.h | 10 ++++++++++
>  2 files changed, 18 insertions(+)
>
> diff --git a/arch/s390/boot/startup.c b/arch/s390/boot/startup.c
> index 8104e0e3d188..297c1062372a 100644
> --- a/arch/s390/boot/startup.c
> +++ b/arch/s390/boot/startup.c
> @@ -253,9 +253,17 @@ static unsigned long setup_kernel_memory_layout(void=
)
>         MODULES_END =3D round_down(__abs_lowcore, _SEGMENT_SIZE);
>         MODULES_VADDR =3D MODULES_END - MODULES_LEN;
>         VMALLOC_END =3D MODULES_VADDR;
> +#ifdef CONFIG_KMSAN
> +       VMALLOC_END -=3D MODULES_LEN * 2;
> +#endif
>
>         /* allow vmalloc area to occupy up to about 1/2 of the rest virtu=
al space left */
>         vmalloc_size =3D min(vmalloc_size, round_down(VMALLOC_END / 2, _R=
EGION3_SIZE));
> +#ifdef CONFIG_KMSAN
> +       /* take 2/3 of vmalloc area for KMSAN shadow and origins */
> +       vmalloc_size =3D round_down(vmalloc_size / 3, PAGE_SIZE);
Is it okay that vmalloc_size is only aligned on PAGE_SIZE?
E.g. above the alignment is _REGION3_SIZE.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DXSKh%3DAmU3mEC7dNmEFk5LaLt%2By%2BTfsVcD0Dn5NsbTBSw%40mai=
l.gmail.com.

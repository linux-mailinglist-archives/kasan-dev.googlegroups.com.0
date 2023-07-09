Return-Path: <kasan-dev+bncBAABB664VCSQMGQEAH5RZWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id D5C6374C0C2
	for <lists+kasan-dev@lfdr.de>; Sun,  9 Jul 2023 05:50:21 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id 41be03b00d2f7-53425d37fefsf3882102a12.3
        for <lists+kasan-dev@lfdr.de>; Sat, 08 Jul 2023 20:50:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1688874620; cv=pass;
        d=google.com; s=arc-20160816;
        b=xI0Kx+tz5Yv/e8ol/EyvXdtOfPlOaQp0mMloBKtS+gJnrp2SUaretYhOuiJSxW2ARi
         kRtlFzbEbfnH+gKfuiyoc/OGPvfG9kjp0idOGaApiihOXtCBO1kGgI+JIiv1ra4wyS2I
         zyeoRybc0Q715IvZfR9VrOEzrNKZV8nXChxROWkFWzm5pLWDeFPefCsPfkOfRuVfGz7h
         Ji4Yf4g+lWHWvMV1eFvoM8WrgwC7JlXETP8N8QKGDVPfBrmO1ES/okdlanytZBcGowzW
         zFpJVGe7xqginc/HxCUjioiec/V0nOo6lnK9TWQZYosedJ96wZmyUIRjJak5ApJazBYV
         pugA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=SxCZCZIAFXlq9oHL3HG6a5Flb15m/UF9yWGyGQtZLI4=;
        fh=FnIIe/vQQbzYprQBokhgFj1uohkP19forFNv5hWqnzY=;
        b=QZv4tEIUyvuz4DCQB8mbBhy4uJ6Z3b9I+LU8TEKIYOtVFsyzIqCs8g7+9jXE/YbWJu
         c1LCiZ350WMQOuOaoDRNAypuz651UFjBCfrs411xa/xG87gl56avWz73sDnta7pQ0ccy
         x0lRJ3rnflg+z9yRi6MTYELV37KUc5/GRPhzlq3EgKzkNKMOCh1eLNgozyrRLQqwXR6j
         EaL1D//vr0pMbOPSh5YT1q9jZ1HJ1BXE3UP1JvaDEOlxhfurJS7P97CAASREb+E8tUcx
         CkTRdjyegHGGUC5o1rZuvFywaZxqBCvOkVYSgydC/Flf+rX2os9WeJF1Htq4Pl/V0fJK
         JdpA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=h3sntgjy;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1688874620; x=1691466620;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=SxCZCZIAFXlq9oHL3HG6a5Flb15m/UF9yWGyGQtZLI4=;
        b=AZ4Q923eau0TYGXh1sobYecWVCMemjvZpo2a/Ay0TeLhm+hax9cuoU3hQx/1cpUtcZ
         itB1y3q9doHcXFTuR51IArOWTDV95tWjrvgimB5qKZ29udBP+3RRHwD3jY/sExukVgDN
         vy7rK4gYdUZ2HsC0XjpntNpRlJyT6UrqmicEY42hnfcScZq7zVxTaaD/4Jb3hrwIoz5u
         gvNctsxTZ9iRq/dbScd2A/An11QrTDTaY1RMw0qFLfVHomimYtffHu8KCKm79sL4Dyy9
         7cnjVy5doT5Dr8jRepMyKx7zepcZLpjayhKPDKKXdwYEf6v3IGyt6OHTbQyeNbJCPG+z
         vhhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1688874620; x=1691466620;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=SxCZCZIAFXlq9oHL3HG6a5Flb15m/UF9yWGyGQtZLI4=;
        b=SgqbRCNBg7DlxmnIQJXhzXtnS0K4Z2fdy+/EBoOzIXLj3dxWYCr+MEZIBHu/vDgyc/
         CyuTM2s/FhSUB0RKBMo6++Cdj0YDTtbuuNviQkwHW5jDNP6LrCHsmkbqoHxTU4lYVk0x
         9SLJnHe94Fr9ZnKbE03YSY1iS041Iv5PLHeJMpfN1BUeddv8QLLKRCRMOmh3c3qanQtT
         RDyLEVgWdwUPY3GLfcvsv5nCUMiaGJPTTw8WNq8pr0UlTq35CrXLK/fwzA6J67T4Wb06
         YTmevsBCsHAyMdfZ5tJZa1Phic3fr3N1tgzCqthQD9SOz5ruG7c1Bw0EDdImR30HDfyM
         CARg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLbQdKtyiL3k+RCP2AcgGvnpCk5Lwk9+oBB/XPCimnAE0CA7tozQ
	Hi8NPSdK+boOUeLql9hQniQ=
X-Google-Smtp-Source: APBJJlGiRjRZxL/USHD5vABqgNfn9YO7aukasTRIh61VhMo7XQtM4cNCE8p4OpavmAY8BN4Eo901og==
X-Received: by 2002:a17:90b:4b88:b0:263:f68d:adca with SMTP id lr8-20020a17090b4b8800b00263f68dadcamr6816660pjb.20.1688874619336;
        Sat, 08 Jul 2023 20:50:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1907:b0:262:d7b2:10e5 with SMTP id
 mp7-20020a17090b190700b00262d7b210e5ls132896pjb.2.-pod-prod-02-us; Sat, 08
 Jul 2023 20:50:18 -0700 (PDT)
X-Received: by 2002:a17:90a:f306:b0:263:f648:e6e1 with SMTP id ca6-20020a17090af30600b00263f648e6e1mr6939994pjb.14.1688874618699;
        Sat, 08 Jul 2023 20:50:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1688874618; cv=none;
        d=google.com; s=arc-20160816;
        b=j2SamWBUtt1xPRA6uN5Rku6z1seArXJDep5fQgBQ0c4f9hLwvan84KY5BX9b3J+dGm
         EZPk8mW32Rr5zHXgjti1OW/Mm54g7d1ffcW0JzSywPkoqtf5JMMCaiD4+jHL+n0MJwSb
         Lgm+ufwspAFmcELNNcr46Xy4iQUgRID6zQ6cYG3MeenCFCgyWzphzq50OpHhv8Fleww1
         l0lARhtg8EyKakUiduuhBXZJPiAO63gbVSPVEdf7FSe21DCI2frEPuDYDqYhJ0mJKZxY
         lehkG/MJBCgBoBhVKQbbRE11hUfaxLLziiO8esQpxtMt8QbmPjFmc5GajNpCkQcE+T/b
         1KZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=/aE9vsrX9e9R1qNeQGQLaMfynFTqRhn3b4qZWtGaxzA=;
        fh=FnIIe/vQQbzYprQBokhgFj1uohkP19forFNv5hWqnzY=;
        b=oXcryMDpfycsvZglmuW8eiABFxuKA+fOt1vhpP2JEhS26hB56jB7sq2RSQANTE5CtY
         qiD9vA8pLM/ms1F/SvsrJ8MPBwPpLApeJ0dvUQDywkh9oIieBRfhQm59q5QdQxkMdBgT
         7eKoKmnNzhj57nh0owsSXUxCcNhKeGIr1OQ0AM81oR82vLmr+FKv2SEhh8idFtYq87cT
         QhO5meTisfJpyFJB5lHzfp6yKqskSx51Avnu7DzPzS+mcqhXAn6yZ8GGvcuotSKsYLG0
         rLiXrv1zO4UH1sOV5qJG9vJN/RMkT8NhA2DH9cW1lY6RGWarih+YK/Q8mIMqlNsQH442
         hbaA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=h3sntgjy;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id x30-20020a17090a38a100b00262f57676a1si485767pjb.1.2023.07.08.20.50.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 08 Jul 2023 20:50:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 1856C60B62
	for <kasan-dev@googlegroups.com>; Sun,  9 Jul 2023 03:50:18 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 68E7FC433C9
	for <kasan-dev@googlegroups.com>; Sun,  9 Jul 2023 03:50:17 +0000 (UTC)
Received: by mail-ed1-f49.google.com with SMTP id 4fb4d7f45d1cf-51e46e83d7fso1665490a12.1
        for <kasan-dev@googlegroups.com>; Sat, 08 Jul 2023 20:50:17 -0700 (PDT)
X-Received: by 2002:aa7:d052:0:b0:51d:a02d:f8fe with SMTP id
 n18-20020aa7d052000000b0051da02df8femr6401474edo.29.1688874615629; Sat, 08
 Jul 2023 20:50:15 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1688369658.git.chenfeiyang@loongson.cn> <cfc7b16d31d0f2dbe08d5d835f34796b2074a35a.1688369658.git.chenfeiyang@loongson.cn>
In-Reply-To: <cfc7b16d31d0f2dbe08d5d835f34796b2074a35a.1688369658.git.chenfeiyang@loongson.cn>
From: Huacai Chen <chenhuacai@kernel.org>
Date: Sun, 9 Jul 2023 11:50:04 +0800
X-Gmail-Original-Message-ID: <CAAhV-H5vKoqm4Cyt7Si5fLmYKvu+YXs3gnm4fr4Tk9USCc97Pg@mail.gmail.com>
Message-ID: <CAAhV-H5vKoqm4Cyt7Si5fLmYKvu+YXs3gnm4fr4Tk9USCc97Pg@mail.gmail.com>
Subject: Re: [PATCH 1/2] LoongArch: relocatable: Provide kaslr_offset() to get
 the kernel offset
To: Feiyang Chen <chenfeiyang@loongson.cn>
Cc: dvyukov@google.com, andreyknvl@gmail.com, loongarch@lists.linux.dev, 
	kasan-dev@googlegroups.com, chris.chenfeiyang@gmail.com, 
	loongson-kernel@lists.loongnix.cn
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=h3sntgjy;       spf=pass
 (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=chenhuacai@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

Hi, Feiyang,

On Tue, Jul 4, 2023 at 8:53=E2=80=AFPM Feiyang Chen <chenfeiyang@loongson.c=
n> wrote:
>
> Provide kaslr_offset() to get the kernel offset when KASLR is enabled.
> Rename reloc_offset to __reloc_offset and export it.
>
> Signed-off-by: Feiyang Chen <chenfeiyang@loongson.cn>
> ---
>  arch/loongarch/include/asm/setup.h |  6 ++++++
>  arch/loongarch/kernel/relocate.c   | 18 ++++++++----------
>  arch/loongarch/kernel/setup.c      |  3 +++
>  3 files changed, 17 insertions(+), 10 deletions(-)
>
> diff --git a/arch/loongarch/include/asm/setup.h b/arch/loongarch/include/=
asm/setup.h
> index 2dca0d1dd90a..39f9964bbdd4 100644
> --- a/arch/loongarch/include/asm/setup.h
> +++ b/arch/loongarch/include/asm/setup.h
> @@ -37,4 +37,10 @@ extern unsigned long __init relocate_kernel(void);
>
>  #endif
>
> +extern unsigned long __reloc_offset;
> +static inline unsigned long kaslr_offset(void)
> +{
> +       return __reloc_offset;
I doubt that we should return random_offset here.

Huacai
> +}
> +
>  #endif /* __SETUP_H */
> diff --git a/arch/loongarch/kernel/relocate.c b/arch/loongarch/kernel/rel=
ocate.c
> index 6c3eff9af9fb..9ba560d514e1 100644
> --- a/arch/loongarch/kernel/relocate.c
> +++ b/arch/loongarch/kernel/relocate.c
> @@ -16,11 +16,9 @@
>  #include <asm/sections.h>
>  #include <asm/setup.h>
>
> -#define RELOCATED(x) ((void *)((long)x + reloc_offset))
> +#define RELOCATED(x) ((void *)((long)x + __reloc_offset))
>  #define RELOCATED_KASLR(x) ((void *)((long)x + random_offset))
>
> -static unsigned long reloc_offset;
> -
>  static inline void __init relocate_relative(void)
>  {
>         Elf64_Rela *rela, *rela_end;
> @@ -154,7 +152,7 @@ static inline void __init update_reloc_offset(unsigne=
d long *addr, long random_o
>  {
>         unsigned long *new_addr =3D (unsigned long *)RELOCATED_KASLR(addr=
);
>
> -       *new_addr =3D (unsigned long)reloc_offset;
> +       *new_addr =3D (unsigned long)__reloc_offset;
>  }
>
>  unsigned long __init relocate_kernel(void)
> @@ -173,7 +171,7 @@ unsigned long __init relocate_kernel(void)
>         if (relocation_addr_valid(location_new))
>                 random_offset =3D (unsigned long)location_new - (unsigned=
 long)(_text);
>  #endif
> -       reloc_offset =3D (unsigned long)_text - VMLINUX_LOAD_ADDRESS;
> +       __reloc_offset =3D (unsigned long)_text - VMLINUX_LOAD_ADDRESS;
>
>         if (random_offset) {
>                 kernel_length =3D (long)(_end) - (long)(_text);
> @@ -187,15 +185,15 @@ unsigned long __init relocate_kernel(void)
>                         "dbar 0 \t\n"
>                         ::: "memory");
>
> -               reloc_offset +=3D random_offset;
> +               __reloc_offset +=3D random_offset;
>
>                 /* The current thread is now within the relocated kernel =
*/
>                 __current_thread_info =3D RELOCATED_KASLR(__current_threa=
d_info);
>
> -               update_reloc_offset(&reloc_offset, random_offset);
> +               update_reloc_offset(&__reloc_offset, random_offset);
>         }
>
> -       if (reloc_offset)
> +       if (__reloc_offset)
>                 relocate_relative();
>
>         relocate_absolute(random_offset);
> @@ -208,9 +206,9 @@ unsigned long __init relocate_kernel(void)
>   */
>  static void show_kernel_relocation(const char *level)
>  {
> -       if (reloc_offset > 0) {
> +       if (__reloc_offset > 0) {
>                 printk(level);
> -               pr_cont("Kernel relocated by 0x%lx\n", reloc_offset);
> +               pr_cont("Kernel relocated by 0x%lx\n", __reloc_offset);
>                 pr_cont(" .text @ 0x%px\n", _text);
>                 pr_cont(" .data @ 0x%px\n", _sdata);
>                 pr_cont(" .bss  @ 0x%px\n", __bss_start);
> diff --git a/arch/loongarch/kernel/setup.c b/arch/loongarch/kernel/setup.=
c
> index 95e6b579dfdd..d7bda711824f 100644
> --- a/arch/loongarch/kernel/setup.c
> +++ b/arch/loongarch/kernel/setup.c
> @@ -65,6 +65,9 @@ struct cpuinfo_loongarch cpu_data[NR_CPUS] __read_mostl=
y;
>
>  EXPORT_SYMBOL(cpu_data);
>
> +unsigned long __reloc_offset __ro_after_init;
> +EXPORT_SYMBOL(__reloc_offset);
> +
>  struct loongson_board_info b_info;
>  static const char dmi_empty_string[] =3D "        ";
>
> --
> 2.39.3
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhV-H5vKoqm4Cyt7Si5fLmYKvu%2BYXs3gnm4fr4Tk9USCc97Pg%40mail.gmai=
l.com.

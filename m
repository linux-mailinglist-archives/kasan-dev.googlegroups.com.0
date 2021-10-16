Return-Path: <kasan-dev+bncBCRKNY4WZECBBT6NVCFQMGQEFBM7TOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id C512242FF99
	for <lists+kasan-dev@lfdr.de>; Sat, 16 Oct 2021 03:11:44 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id r13-20020a92440d000000b002498d6b85c1sf5266262ila.5
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Oct 2021 18:11:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634346703; cv=pass;
        d=google.com; s=arc-20160816;
        b=vpi1nZxQAuJo1fFofVYyesEzcwZqGBgfTdSDMvQrYnsqeM4O3g4X9w7gmlJqCgQsFY
         gHD+y0kCcp8RkihR5esVmHRVzK12YslAy3BWIkHQu6AGwBaVOdwidpmxgpDmNYLPN3Kz
         rkbUIEJ3iFO/6s9YgOMAGrUvZOZ+BmTVgYkJY5oKyffC2FoR71sMPMyh14ZmzG7DJASh
         LUcsx+lAxPbO9epmuMs/zgKAGeWZfu1e8NDPiUZzqxSkQq+0qmN2Fr/w8Tgk8X/jXc0B
         C/WaKAO+kWOaA5RKasuvk2SVOnOLDN1at8D4yD1VFNh6jO46pnsB+DTYW4TE7QC0AQNj
         Sxnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:to:from:cc:in-reply-to:subject:date:sender
         :dkim-signature;
        bh=3ym+wfZel2WftQOcl6zAsWHKVj7QlturchMiPzlaEus=;
        b=ZVfA8326LMfOOBMsKnT1S4xHKGG7mTeSTXnd+cDGXlEJXsa7vmoBwbWtz9tgZzw429
         f0H7JyWsUQVCjwHpdQMToFDZSZt6BHxmYQLan2gkR7WlPfqxwHJZgyOB+UkBTzPJlwtl
         zYuvTh2w/s5o3+jWkQV5p4h6fG9MAjIriwKYFzpnFMY+p+sirTGsB+NSTDethZ8u51xP
         R0SKKYS3lEoMP1tvKADblNSL4LrI3afpVZ+oxmpKYqhS8J4mgBYjLAPtNkMHnOLGwRAA
         XP946UJDjSCMCoYA1s3TxgNKS3q3FAjBErSPAcbbNnwdTIiIk9PoO6wL1EvkLJA5ah2f
         T0ig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112 header.b=GZKEtGQX;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3ym+wfZel2WftQOcl6zAsWHKVj7QlturchMiPzlaEus=;
        b=f54qeqUdx6EEfzQ/ftskfuY+Mc9EUVfC31ZQeGzTXxxXQxCv6wT2/1v8aGGfBLJq2P
         LJVp8T7xltpevyZfG6ufXB69DnWQ8DWTYJyL7rRWaAHVAACCVJjP0HUmSMB1QD1PNE1G
         /b5PItk7axtcPHOwIMfQ0cfmwDE290wWNZj2wFqOx2hwGLSPS3+z+ydt3pj/rISJLXL0
         e8w8cnsex99lQH/D5oMid/vOdPdFs0TV7Vc+q6gdmIOp/k0id/0DQdm/DbTMEx0OVLRK
         QG2qQxaR2031OAtQfHJSC9ljlJf4zwb5oVkLYwgYF6EscTG7I9vjPU3Z9as76l5D/Bgf
         ymMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3ym+wfZel2WftQOcl6zAsWHKVj7QlturchMiPzlaEus=;
        b=A0V/Xy6a3ybrsyAUvH1t3MruI8jrzWGzwWi+iOeujXR4vk3VelJ9fO11kXcNLNpv5V
         1pS49M2peinqe1SfWzCnNe+CLsZXFOs0UZRYiHN5jxE3t8+AWfNexgEf063M18HsKfHs
         zejV5BAGUvglSVPTV6R6cGDFBOBwINayC5fBJVLoASllI1lG6pkv11obwq9NOE7Eu8tb
         S1N2XtCnFXE5ExlmseryPfCuudj44uh38c5Z5it0vxAnhcC8z2GvwqX19cXw8Cyxycvc
         sDOfwx+g+nXAfIjNhfUL2PoQnnpewhxBTwglpiLx7sFRZ0R299CvkfvubwCGk/RxqqJV
         7nhQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5335SDp/4sAjD1lFUNm0+S6gYfixJ6+VPCYKS5o4+Gkfv/BuFjVG
	MPxxKFtlkXcNSNdoC0psd9E=
X-Google-Smtp-Source: ABdhPJyuJtWqwJ7MzsvmFaGzsbEET3tT8khoKi00JsBQ5eJuiFy4Z2UlUcDa/YuBiVxX37p/APvqoQ==
X-Received: by 2002:a92:1a42:: with SMTP id z2mr6059046ill.270.1634346703510;
        Fri, 15 Oct 2021 18:11:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2182:: with SMTP id j2ls175357ila.9.gmail; Fri, 15
 Oct 2021 18:11:43 -0700 (PDT)
X-Received: by 2002:a05:6e02:bf4:: with SMTP id d20mr6275446ilu.146.1634346703163;
        Fri, 15 Oct 2021 18:11:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634346703; cv=none;
        d=google.com; s=arc-20160816;
        b=xIIhg2cKjFkEQGppIACVs9SzjYJEDDF175VT920CTjCuhT9h7ZnlxnnDpPs2J3x8Jo
         ewQs/EakteIyD6cq6cHajC2j7nKTwNkymuTVjIHEPgP5w9QlfJfLCgIclGNLU4kuigPA
         +duUc+hQTJg5CN9S7SRhMYRyD68Ei75CRhlxtNYoZPJFMAWDLbo35k9s/W+ZlKfU0fAB
         bsBfzaKz2Zb61FDHWKcWaPhXfDnGQ7PyILJnHFoTZg8y1d72NXwcBUFWH9nuWKwhmTdV
         3nBY97oyRhvnQ7dlvAL4HeJIvUNPe2paoRyXPPWhttD36cScZ4/JrgT7XXH//xlkNQWU
         IvCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=ZnmWcpYjZ93+9/USsjI5yc08CI3gidamSDoWKAiSGj8=;
        b=dIbkiIbTydeMxkeRrRS/hOaeWJPCOtqCko6+8s0lyuwQx7bVWnFo9WlwhAKhReQS8o
         NTtSQngzliyimEWLUfoAu6bA1v6ytuRIm0+muwfqmoEAG1yyaZV/2s8xP5YzH1uuprOr
         JRv4j53EE/4k0WYct0tYf2C5jEPyS09cNdIyh6jC7LzKjCfpgFxEHSvJtg987LmulOw6
         J9Ccyo587nG37hfMAa1HoEFpt95epXQIRf8hCMUg/63LIrk1U1U8cHOCu6Ks5K+vR9Uw
         0YGznSu8FWU7di1aG8kihctiyMCHkdCtZ4tt85r5/Nc9POM1sIptuQMfYiAvjxmzPcUP
         wuVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112 header.b=GZKEtGQX;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pf1-x432.google.com (mail-pf1-x432.google.com. [2607:f8b0:4864:20::432])
        by gmr-mx.google.com with ESMTPS id p5si515443ilo.5.2021.10.15.18.11.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Oct 2021 18:11:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::432 as permitted sender) client-ip=2607:f8b0:4864:20::432;
Received: by mail-pf1-x432.google.com with SMTP id q19so9769594pfl.4
        for <kasan-dev@googlegroups.com>; Fri, 15 Oct 2021 18:11:42 -0700 (PDT)
X-Received: by 2002:aa7:8189:0:b0:44c:293a:31e4 with SMTP id g9-20020aa78189000000b0044c293a31e4mr14844220pfi.51.1634346702295;
        Fri, 15 Oct 2021 18:11:42 -0700 (PDT)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id pj12sm6334412pjb.19.2021.10.15.18.11.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 Oct 2021 18:11:41 -0700 (PDT)
Date: Fri, 15 Oct 2021 18:11:41 -0700 (PDT)
Subject: Re: [PATCH] kasan: Always respect CONFIG_KASAN_STACK
In-Reply-To: <afeaea5f-70f2-330f-f032-fb0c8b5d0aa5@ghiti.fr>
CC: nathan@kernel.org, elver@google.com, akpm@linux-foundation.org,
  ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
  ndesaulniers@google.com, Arnd Bergmann <arnd@arndb.de>, kasan-dev@googlegroups.com,
  linux-kernel@vger.kernel.org, llvm@lists.linux.dev, linux-riscv@lists.infradead.org,
  Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu, linux-mm@kvack.org
From: Palmer Dabbelt <palmer@dabbelt.com>
To: alex@ghiti.fr
Message-ID: <mhng-8b034488-1592-442a-a206-203c73b3b3bc@palmerdabbelt-glaptop>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20210112.gappssmtp.com header.s=20210112
 header.b=GZKEtGQX;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Thu, 14 Oct 2021 11:31:00 PDT (-0700), alex@ghiti.fr wrote:
> Hi Nathan,
>
> Le 14/10/2021 =C3=A0 18:55, Nathan Chancellor a =C3=A9crit=C2=A0:
>> On Fri, Oct 08, 2021 at 11:46:55AM -0700, Palmer Dabbelt wrote:
>>> On Thu, 23 Sep 2021 07:59:46 PDT (-0700), nathan@kernel.org wrote:
>>>> On Thu, Sep 23, 2021 at 12:07:17PM +0200, Marco Elver wrote:
>>>>> On Wed, 22 Sept 2021 at 22:55, Nathan Chancellor <nathan@kernel.org> =
wrote:
>>>>>> Currently, the asan-stack parameter is only passed along if
>>>>>> CFLAGS_KASAN_SHADOW is not empty, which requires KASAN_SHADOW_OFFSET=
 to
>>>>>> be defined in Kconfig so that the value can be checked. In RISC-V's
>>>>>> case, KASAN_SHADOW_OFFSET is not defined in Kconfig, which means tha=
t
>>>>>> asan-stack does not get disabled with clang even when CONFIG_KASAN_S=
TACK
>>>>>> is disabled, resulting in large stack warnings with allmodconfig:
>>>>>>
>>>>>> drivers/video/fbdev/omap2/omapfb/displays/panel-lgphilips-lb035q02.c=
:117:12:
>>>>>> error: stack frame size (14400) exceeds limit (2048) in function
>>>>>> 'lb035q02_connect' [-Werror,-Wframe-larger-than]
>>>>>> static int lb035q02_connect(struct omap_dss_device *dssdev)
>>>>>>             ^
>>>>>> 1 error generated.
>>>>>>
>>>>>> Ensure that the value of CONFIG_KASAN_STACK is always passed along t=
o
>>>>>> the compiler so that these warnings do not happen when
>>>>>> CONFIG_KASAN_STACK is disabled.
>>>>>>
>>>>>> Link: https://github.com/ClangBuiltLinux/linux/issues/1453
>>>>>> References: 6baec880d7a5 ("kasan: turn off asan-stack for clang-8 an=
d earlier")
>>>>>> Signed-off-by: Nathan Chancellor <nathan@kernel.org>
>>>>>
>>>>> Reviewed-by: Marco Elver <elver@google.com>
>>>>
>>>> Thanks!
>>>>
>>>>> [ Which tree are you planning to take it through? ]
>>>>
>>>> Gah, I was intending for it to go through -mm, then I cc'd neither
>>>> Andrew nor linux-mm... :/ Andrew, do you want me to resend or can you
>>>> grab it from LKML?
>>>
>>> Acked-by: Palmer Dabbelt <palmerdabbelt@google.com>
>>>
>>> (assuming you still want it through somewhere else)
>>
>> Thanks, it is now in mainline as commit 19532869feb9 ("kasan: always
>> respect CONFIG_KASAN_STACK").
>>
>>>>> Note, arch/riscv/include/asm/kasan.h mentions KASAN_SHADOW_OFFSET in
>>>>> comment (copied from arm64). Did RISC-V just forget to copy over the
>>>>> Kconfig option?
>>>>
>>>> I do see it defined in that file as well but you are right that they d=
id
>>>> not copy the Kconfig logic, even though it was present in the tree whe=
n
>>>> RISC-V KASAN was implemented. Perhaps they should so that they get
>>>> access to the other flags in the "else" branch?
>>>
>>> Ya, looks like we just screwed this up.  I'm seeing some warnings like
>>>
>>>     cc1: warning: =E2=80=98-fsanitize=3Dkernel-address=E2=80=99 with st=
ack protection is not supported without =E2=80=98-fasan-shadow-offset=3D=E2=
=80=99 for this target
>>
>> Hmmm, I thought I did a GCC build with this change but I must not have
>> :/
>>
>>> which is how I ended up here, I'm assuming that's what you're talking a=
bout
>>> here?  LMK if you were planning on sending along a fix or if you want m=
e to
>>> go figure it out.
>>
>> I took a look at moving the logic into Kconfig like arm64 before sending
>> this change and I did not really understand it well enough to do so. I
>> think it would be best if you were able to do that so that nothing gets
>> messed up.
>>
>
> I'll do it tomorrow, I'm the last one who touched kasan on riscv :)

Any luck?  I tried what I think is the simple way to do it last week,=20
(merging with Linus' tree is turning these warnings into build=20
failures) but it's hanging on boot.  Not sure what's going on

    diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
    index c3f3fd583e04..d3998b4a45f1 100644
    --- a/arch/riscv/Kconfig
    +++ b/arch/riscv/Kconfig
    @@ -212,6 +212,12 @@ config PGTABLE_LEVELS
     config LOCKDEP_SUPPORT
            def_bool y
   =20
    +config KASAN_SHADOW_OFFSET
    +       hex
    +       depends on KASAN_GENERIC
    +       default 0xdfffffc800000000  if 64BIT
    +       default 0xffffffff          if 32BIT
    +
     source "arch/riscv/Kconfig.socs"
     source "arch/riscv/Kconfig.erratas"
   =20
    diff --git a/arch/riscv/include/asm/kasan.h b/arch/riscv/include/asm/ka=
san.h
    index a2b3d9cdbc86..b00f503ec124 100644
    --- a/arch/riscv/include/asm/kasan.h
    +++ b/arch/riscv/include/asm/kasan.h
    @@ -30,8 +30,7 @@
     #define KASAN_SHADOW_SIZE      (UL(1) << ((CONFIG_VA_BITS - 1) - KASAN=
_SHADOW_SCALE_SHIFT))
     #define KASAN_SHADOW_START     KERN_VIRT_START
     #define KASAN_SHADOW_END       (KASAN_SHADOW_START + KASAN_SHADOW_SIZE=
)
    -#define KASAN_SHADOW_OFFSET    (KASAN_SHADOW_END - (1ULL << \
    -                                       (64 - KASAN_SHADOW_SCALE_SHIFT)=
))
    +#define KASAN_SHADOW_OFFSET    _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
   =20
     void kasan_init(void);
     asmlinkage void kasan_early_init(void);

>
> Thanks,
>
> Alex
>
>> Cheers,
>> Nathan
>>
>> _______________________________________________
>> linux-riscv mailing list
>> linux-riscv@lists.infradead.org
>> http://lists.infradead.org/mailman/listinfo/linux-riscv
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/mhng-8b034488-1592-442a-a206-203c73b3b3bc%40palmerdabbelt-glaptop=
.

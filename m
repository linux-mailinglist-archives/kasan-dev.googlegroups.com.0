Return-Path: <kasan-dev+bncBC6L3EFVX4NRBOP2R2YAMGQECOC53JA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id B43EA88D65D
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Mar 2024 07:31:23 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-515adcf2004sf2517058e87.2
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Mar 2024 23:31:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711521083; cv=pass;
        d=google.com; s=arc-20160816;
        b=vrw3c0oI9QviH2RbpP2Rs0ThNPRgyJmq67UX58hrMf9nbDDPZDPMnNmH7+7WWjW93e
         2Xx0F2/gg+6v3ySzDbQRXyKKjWO9GLCDb8hAcBNOkKbtDc+KUxUniSJn8qNlPfF+h58l
         mOIloam4yIQReTDDIiFTn62y2LunJMMzJWfS59km88FbsE2IRKCfzA4WHA5Uu9N6DTvu
         8y3Do6wVHPUMky3xy1DA597sORx6jnAWbNP3Nv+Q44SDVCs8v4w3vE2sMHlqXZEKhnvk
         nLOOEXmOX6aVJfTjgyuKNuDC3dTY9zTyEQSApDleim7q04zlVjY4emUWVj8EoS5QmmXh
         qkXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=xGQbHeBiQmab7RN3aQ3xFMUB7nVULm1dBbOZKga6mTg=;
        fh=2WGriA8cGS1XnLPHB5eus9V9Pbue58WubgoHCyx7r64=;
        b=pKgLIrIOomCnnuh+/QrCIYZNjEgTKzJPiGzbeEX7GVTC6eoqXRe2E7Ei7/MwBpaVC/
         8kmsHZKUj7Fqaen+tUgzN3Rl6irSd8i5t2yvfqaM7xCwq8uCwmetc2gemfQA3rl4Sc3i
         6tP01OpMxDbJo/iHaWvQXohRu7lp+3xxLY/PICFkCVWLf33o8Ups61Lv1r040yR7ENWZ
         XL96yK2kXPBI1MRoxSf5jeG8HKtzSM9sdW9wYSoRC+PQF5fl9ft9FENN5XZwZcf9doNk
         WGlZ1mBt2elzjmsSIOJY7ktSHgDttB4z3rDUY1q+i9CAhNj/MlROspJ65QNmXZLi6uMl
         9InQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=google header.b=B79lycfs;
       spf=pass (google.com: domain of nik.borisov@suse.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=nik.borisov@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711521083; x=1712125883; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=xGQbHeBiQmab7RN3aQ3xFMUB7nVULm1dBbOZKga6mTg=;
        b=MDOdiPU9OJ9TgEab9vJUoltrKHkU1wPJFLJVNnl7ZL70+X7lzlUyHBPR3rtUepC0SJ
         PyHRVz5mVqdAXAUDnadTobQqBgdeC+JYsNbMo2avFxZkY4LMls5WVRJU/RXVMTBDcLZh
         ignWYHHc69sq7v8LKGT1N/xffuzy6fHwdK13pshXI/6uxIHc0EPn1zIDJA0ry9QbPH9G
         593Vh7uuJKoXQiEWXEu5ijzG2XRP0o8lRwccJ6KI76YOhXpXbzpkoeoAE2uKg2d6E1ni
         Z9NNwrOfMCEvXlYyxfBypWmx3q05iZ05ChrsxWgTPUh8YxANkDWQZCPM4rYuPrMYcBIN
         W/Cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711521083; x=1712125883;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xGQbHeBiQmab7RN3aQ3xFMUB7nVULm1dBbOZKga6mTg=;
        b=DYwk6hf6WMAufQgaJU1RJRrKZjWILA1VD2Wr6N+ZFjco5OIlQ31ysUkFcGp7xeiOcQ
         EZ9W8bAKC4Y8rnDRG8LXl+PEeMdrje+afTU/EnQFpC57bmvJa+GwOrlFlRJ434USjpb0
         UO/V9hEjgw44XiAWivavpUoLzEGubJqR2tSa8OkrzJABGfSyAUUbo01FUVFZhCKQdSl4
         nSrC+NYV3UFeyQt8YXCka/++sslIqDAZVs+TaOu2sEOCExVz/xA+TJMinN96808A5SvO
         V5xBMVmpp8+2aZGvAhkfPKePVDUaR15xUj9iG/PSrxUUqlKEcTmLpqx5NABId9s7904J
         fc6Q==
X-Forwarded-Encrypted: i=2; AJvYcCVdFyX0EjgKWrNV79E9QEVfpb2/2YucUChWKPk5ST09otdZ0uyp0NUNaQHrShrreAorIDj7W6mFI82LYhHyXBrxm2HVOtP9sg==
X-Gm-Message-State: AOJu0YzvI+nCqblLZyzyg4ATcRMqqGQugpnCUzl4uzHb9soRRPS5UMU+
	zgg9O4ujAgD4fVNnRh5gR6c7rA81S5HrmwWu9ExVVisK7Kf9GjAU
X-Google-Smtp-Source: AGHT+IFtFsFSEYX7BwSdo7N8foXhrf5v9JEq+NrTWxURgjokE9qBTXZLfMtBPUhrZQ6nY0HGgsNa+g==
X-Received: by 2002:ac2:5b4f:0:b0:515:b08f:41b4 with SMTP id i15-20020ac25b4f000000b00515b08f41b4mr204135lfp.36.1711521081661;
        Tue, 26 Mar 2024 23:31:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:281b:b0:515:ad02:21c6 with SMTP id
 cf27-20020a056512281b00b00515ad0221c6ls15614lfb.0.-pod-prod-08-eu; Tue, 26
 Mar 2024 23:31:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU31iyG3fxV5CbTFohtpvHtmswn+tcQKBXI8Os/5jdZWuagPpBshYPSIYpdDZYf8eXbvkf6G3UJVzZN9yEHnNYBatzeRPTmfhTONQ==
X-Received: by 2002:a05:6512:539:b0:513:3214:ae03 with SMTP id o25-20020a056512053900b005133214ae03mr203304lfc.69.1711521079507;
        Tue, 26 Mar 2024 23:31:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711521079; cv=none;
        d=google.com; s=arc-20160816;
        b=ObqDjb/CnaRGIksdRUVmmsybSSrDzyChkkiLrnG0n2DyS38W27Lx6D6e5addHGAxYB
         yJUIsKzc81ZKQJxVVdiFm2ZK97Rsd+RNREhyRMB98vw+XwwV1UkBRDtr6hZpP9sNeagV
         x7YLTy1OTm/es0TvFz1XL8BTJsRi+jXUXrs1n5qs3Ih2TiJQZW2INvO682aMjHSskzxw
         jDEpbgPuJMOTE9NSB5f9dDUC6uUn1g7HXmV5gWHq2SpqgkpgMk5lHT+3jAKlQsUrDhf5
         oqTxjkMThSaWUOonJUUB4psgqg3jPFPgC9gQJw1L+2fpFE3PljRcRckY8yIr5NdU3ufX
         r1Ow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=lhpFZQpOMPEuWhNyecOS9hDFqqTSnzNsHuwPkusroyo=;
        fh=MW7iGAb6CSuRVsXMhYRVo94pi9XH3Y+cA7yEccWxwj8=;
        b=Myu5YLlBpvh8c7XIz8jRM4XwLy7dsSDZbI1tMYIuvQj9cVhxgul3haunaa5888/dOE
         ndg/2ULaPnbdzlYTh9f+5nPhOpr9ToUIo+smeAySjRzbHrunuULSpYGycQxVwBwY+zI3
         XK6pUnja3ptxk9rn2pu4PaJQWsotK2eMDPvuDIwkDMt7YrHZpKhMtOtXoJ7FJki+JLeP
         V2JebCmfug3MIw7I3GrNK1J+scFO61OxsnH4LkvYe6CiTSct/CfHrQWU+ic2GNpdnwpA
         tSqsV6dXplxMm6nJ1n0IffMWS4IcysCkjPxYERlcK8x1QPUT0b6gvZUA5EV8W987eQjG
         JVxQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=google header.b=B79lycfs;
       spf=pass (google.com: domain of nik.borisov@suse.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=nik.borisov@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from mail-wm1-x32d.google.com (mail-wm1-x32d.google.com. [2a00:1450:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id c3-20020ac25f63000000b00515aa2b9262si182894lfc.2.2024.03.26.23.31.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Mar 2024 23:31:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of nik.borisov@suse.com designates 2a00:1450:4864:20::32d as permitted sender) client-ip=2a00:1450:4864:20::32d;
Received: by mail-wm1-x32d.google.com with SMTP id 5b1f17b1804b1-41495dcea8eso108685e9.3
        for <kasan-dev@googlegroups.com>; Tue, 26 Mar 2024 23:31:19 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU6eCxIXMkHXGSoQkeAhEBe3gHVTlUJ023L6ZZhPCMRNAImRU8YkTHkRZfiA9peRPwLOc9jCdn5JuUYopbBoeLmZOBAV+2Bxkiv5A==
X-Received: by 2002:a05:600c:a47:b0:412:f572:5318 with SMTP id c7-20020a05600c0a4700b00412f5725318mr303758wmq.11.1711521078647;
        Tue, 26 Mar 2024 23:31:18 -0700 (PDT)
Received: from ?IPV6:2a10:bac0:b000:73fa:7285:c2ff:fedd:7e3a? ([2a10:bac0:b000:73fa:7285:c2ff:fedd:7e3a])
        by smtp.gmail.com with ESMTPSA id f6-20020a05600c4e8600b004148ff6ef54sm1113036wmq.29.2024.03.26.23.31.17
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Mar 2024 23:31:18 -0700 (PDT)
Message-ID: <26803d4f-0e58-4ca8-8f09-1a5d52a67ac4@suse.com>
Date: Wed, 27 Mar 2024 08:31:15 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] kbuild: Disable KCSAN for autogenerated *.mod.c
 intermediaries
Content-Language: en-US
To: Borislav Petkov <bp@alien8.de>, Masahiro Yamada <masahiroy@kernel.org>,
 Nathan Chancellor <nathan@kernel.org>, Nicolas Schier <nicolas@fjasle.eu>,
 linux-kbuild@vger.kernel.org
Cc: Marco Elver <elver@google.com>, Josh Poimboeuf <jpoimboe@kernel.org>,
 Paul Menzel <pmenzel@molgen.mpg.de>, Thomas Gleixner <tglx@linutronix.de>,
 Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>,
 Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com,
 David Kaplan <David.Kaplan@amd.com>
References: <0851a207-7143-417e-be31-8bf2b3afb57d@molgen.mpg.de>
 <47e032a0-c9a0-4639-867b-cb3d67076eaf@suse.com>
 <20240326155247.GJZgLvT_AZi3XPPpBM@fat_crate.local>
 <80582244-8c1c-4eb4-8881-db68a1428817@suse.com>
 <20240326191211.GKZgMeC21uxi7H16o_@fat_crate.local>
 <CANpmjNOcKzEvLHoGGeL-boWDHJobwfwyVxUqMq2kWeka3N4tXA@mail.gmail.com>
 <20240326202548.GLZgMvTGpPfQcs2cQ_@fat_crate.local>
From: "'Nikolay Borisov' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20240326202548.GLZgMvTGpPfQcs2cQ_@fat_crate.local>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: nik.borisov@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=google header.b=B79lycfs;       spf=pass
 (google.com: domain of nik.borisov@suse.com designates 2a00:1450:4864:20::32d
 as permitted sender) smtp.mailfrom=nik.borisov@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Nikolay Borisov <nik.borisov@suse.com>
Reply-To: Nikolay Borisov <nik.borisov@suse.com>
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



On 26.03.24 =D0=B3. 22:25 =D1=87., Borislav Petkov wrote:
> On Tue, Mar 26, 2024 at 08:33:31PM +0100, Marco Elver wrote:
>> I think just removing instrumentation from the mod.c files is very reaso=
nable.
>=20
> Thanks!
>=20
> @Masahiro: pls send this to Linus now as the commit which adds the
> warning is in 6.9 so we should make sure we release it with all issues
> fixed.
>=20
> Thx.
>=20
> ---
> From: "Borislav Petkov (AMD)" <bp@alien8.de>
> Date: Tue, 26 Mar 2024 21:11:01 +0100
>=20
> When KCSAN and CONSTRUCTORS are enabled, one can trigger the
>=20
>    "Unpatched return thunk in use. This should not happen!"
>=20
> catch-all warning.
>=20
> Usually, when objtool runs on the .o objects, it does generate a section
> .return_sites which contains all offsets in the objects to the return
> thunks of the functions present there. Those return thunks then get
> patched at runtime by the alternatives.
>=20
> KCSAN and CONSTRUCTORS add this to the the object file's .text.startup
> section:
>=20
>    -------------------
>    Disassembly of section .text.startup:
>=20
>    ...
>=20
>    0000000000000010 <_sub_I_00099_0>:
>      10:   f3 0f 1e fa             endbr64
>      14:   e8 00 00 00 00          call   19 <_sub_I_00099_0+0x9>
>                            15: R_X86_64_PLT32      __tsan_init-0x4
>      19:   e9 00 00 00 00          jmp    1e <__UNIQUE_ID___addressable_c=
ryptd_alloc_aead349+0x6>
>                            1a: R_X86_64_PLT32      __x86_return_thunk-0x4
>    -------------------
>=20
> which, if it is built as a module goes through the intermediary stage of
> creating a <module>.mod.c file which, when translated, receives a second
> constructor:
>=20
>    -------------------
>    Disassembly of section .text.startup:
>=20
>    0000000000000010 <_sub_I_00099_0>:
>      10:   f3 0f 1e fa             endbr64
>      14:   e8 00 00 00 00          call   19 <_sub_I_00099_0+0x9>
>                            15: R_X86_64_PLT32      __tsan_init-0x4
>      19:   e9 00 00 00 00          jmp    1e <_sub_I_00099_0+0xe>
>                            1a: R_X86_64_PLT32      __x86_return_thunk-0x4
>=20
>    ...
>=20
>    0000000000000030 <_sub_I_00099_0>:
>      30:   f3 0f 1e fa             endbr64
>      34:   e8 00 00 00 00          call   39 <_sub_I_00099_0+0x9>
>                            35: R_X86_64_PLT32      __tsan_init-0x4
>      39:   e9 00 00 00 00          jmp    3e <__ksymtab_cryptd_alloc_ahas=
h+0x2>
>                            3a: R_X86_64_PLT32      __x86_return_thunk-0x4
>    -------------------
>=20
> in the .ko file.
>=20
> Objtool has run already so that second constructor's return thunk cannot
> be added to the .return_sites section and thus the return thunk remains
> unpatched and the warning rightfully fires.
>=20
> Drop KCSAN flags from the mod.c generation stage as those constructors
> do not contain data races one would be interested about.
>=20
> Debugged together with David Kaplan <David.Kaplan@amd.com> and Nikolay
> Borisov <nik.borisov@suse.com>.
>=20
> Reported-by: Paul Menzel <pmenzel@molgen.mpg.de>
> Signed-off-by: Borislav Petkov (AMD) <bp@alien8.de>
> Link: https://lore.kernel.org/r/0851a207-7143-417e-be31-8bf2b3afb57d@molg=
en.mpg.de
> ---
>   scripts/Makefile.modfinal | 2 +-
>   1 file changed, 1 insertion(+), 1 deletion(-)
>=20
> diff --git a/scripts/Makefile.modfinal b/scripts/Makefile.modfinal
> index 8568d256d6fb..79fcf2731686 100644
> --- a/scripts/Makefile.modfinal
> +++ b/scripts/Makefile.modfinal
> @@ -23,7 +23,7 @@ modname =3D $(notdir $(@:.mod.o=3D))
>   part-of-module =3D y
>  =20
>   quiet_cmd_cc_o_c =3D CC [M]  $@
> -      cmd_cc_o_c =3D $(CC) $(filter-out $(CC_FLAGS_CFI) $(CFLAGS_GCOV), =
$(c_flags)) -c -o $@ $<
> +      cmd_cc_o_c =3D $(CC) $(filter-out $(CC_FLAGS_CFI) $(CFLAGS_GCOV) $=
(CFLAGS_KCSAN), $(c_flags)) -c -o $@ $<
>  =20
>   %.mod.o: %.mod.c FORCE
>   	$(call if_changed_dep,cc_o_c)


Reviewed-by: Nikolay Borisov <nik.borisov@suse.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/26803d4f-0e58-4ca8-8f09-1a5d52a67ac4%40suse.com.

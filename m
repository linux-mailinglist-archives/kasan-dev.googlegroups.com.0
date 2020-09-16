Return-Path: <kasan-dev+bncBCM33EFK7EJRBQPRQ35QKGQEVOS467A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A8CD26BD9E
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Sep 2020 09:03:30 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id a17sf862986lfl.4
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Sep 2020 00:03:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600239809; cv=pass;
        d=google.com; s=arc-20160816;
        b=CAc1p1z0TVTlnxY6jUN7pDP0RbwoawAbeoeNGrOJ5DdLsAiPV/xBrccS9FhjECEqLU
         8wt9qB4VxNN1bDatheQ9mRVi/JEEZ9luzGSsuchxMDAWhbKq3Va1+hyx4v0QMH5rXEhd
         brsDpWI/5+IjI9KZ0JhGdEe29NU1w61Bdvvo10ueYeSupUyfsIPuMFcjyDtX1D9E9izO
         oEilbPNyi9fIFGboX+aGAhLqzDERc/1hAiAdONE90oGDxJDTDj81vylkel7+BfiTmZQl
         pIw9gX5GER2uNXhHa12rI0Q0jBCn/VkY8/ILWdkl7hBSnechI2CXvwG3QnB/RZb72jQv
         P/PQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=pHf58vP6EkSSaDpiuZ+3oHnxSKz4aUrNvrnIM08mx9s=;
        b=TD5UL1B7BSSHiWb/bjZSMj93AHZocUYcwuw85MM6my22KNbC2DN2FLUyeL449DxZDR
         y9LZDzKKbpw60Iyw5SzGQEdU8m9EuT5ah4CoFqmNaqH3DD6WjlJWWHzTUJUWl8qxN1G9
         ae4O0A3QLNjWeylVkFRovOx8bih1jFH/lvWJ2qVDS1yx6xswguBwPFhcF5eujff9PvK0
         FyfhGECLCuLEuRl49MYrUbR7ao0ELb1wO7qQpLeHfQX6r25Sm+eh9hwlp6rkKZmnLjtn
         /wA2MeabT2Lcbr2kOK1tBDVBRUNlY1v5YSAFlqYOgD6o0NkmiIOnG+Nws3RqlnEoRDhV
         wsAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=X+UdvNV0;
       spf=pass (google.com: domain of ilie.halip@gmail.com designates 2a00:1450:4864:20::144 as permitted sender) smtp.mailfrom=ilie.halip@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pHf58vP6EkSSaDpiuZ+3oHnxSKz4aUrNvrnIM08mx9s=;
        b=fhuU9s3ioNTEJr3TRs3tKZzZYWtmBFGhz68E7UAu8abmO7kFM6PCYz9668XsLHPNio
         c9DkdNV0ibaR3EQDutLeTkxQGoXf5qqIFRIHUs8pG6qxD0yejrG3lq8IUlaVz6/LwRDg
         s6mCFo8HRrewkD56POYlUslljHQS96UKGa8qDBQZJoMEId/DYggMFnrELt5lfrLsPAb6
         y6QCwrQKNacUoCsH7gY2n1MQzMNbNgvhqXESR58komfrQYIo4xvGyxxHfsufYNNswJtc
         ls8p6cdR/0bSTjNYthzrSly184ObmOlJVzIPbat8YLfKBnXsNyqOlsKq7ca5Z4Dtxj9i
         pD4A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pHf58vP6EkSSaDpiuZ+3oHnxSKz4aUrNvrnIM08mx9s=;
        b=VPAwMgBklcY77KNsRyp8JxfMslWkitMOqnPINiHQskEfcURSEoFdP/1PEIw32RIDUu
         nFd7aO7rVUBYRfdHR2PEHDfXK8yLo3pRRviNw5OgAY2M7W3t5/4QDkx4V0hI4GY6lZSo
         nZaNqI33vTWS5e0wgMFRLYgThqqmQEMjKzGTxc/0KhY0MSAzUaDpENptAiUj1tnMRnYb
         rq6YJs3Zv7SU9b9XRuLc39Ig2AYfeUnoO2xKytF6tGZh2q7XZrpLneRRhGnGhOhU+OMv
         tUK4kkscawX18T1VHCcVAqKUpX/Gvn7rBKky/TG89kdT2lyOFzCpKa/fj8jAtE8v6SGK
         0uYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pHf58vP6EkSSaDpiuZ+3oHnxSKz4aUrNvrnIM08mx9s=;
        b=jkbrYXFnfSEpIprrKGGJhUuoFER2Y9ofMBOvQjeLnk1sacTOVfZmQiid4DQ7WM2YSf
         UF7HWJnfakj91tch7yo6KaNWub/jbNnod6Fh6x8vxhhDuFDbin3ef/UIIqbJB3XOfoHp
         TN2mvBqfDMMrj+dCA95fEaXNMYYkRuZ6qFamWtMqBUZoxQ4Eo4qxrn90070i5xeU8NVZ
         1n/U6GwlcFoXGA5mvsmInJ6AI93RcgDXg+4niisdmVxXiyjwFyGPMDW6AhKuuR3PHznV
         G266Bhm6QtDckZz3Okokz8mf0EPdcs+9DIqGBPfzArZlFQyiXAKQi5KsBTqL96Q60ZpO
         Fz1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531HCYG+rOafXp570ob0GKtP2x54VmaMb7tqvG2Cirpfw/rIFkvY
	UCjMneEOgoe1Fn/3Axw3ZXc=
X-Google-Smtp-Source: ABdhPJxt2UGUfazW+wU96s6bSa5YEB27SW3jUA66mmn3D1yZqHadqQNFHo4LfmmWhwSKrQ7mcBVdDw==
X-Received: by 2002:a05:651c:134a:: with SMTP id j10mr8622633ljb.337.1600239809600;
        Wed, 16 Sep 2020 00:03:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:554:: with SMTP id 81ls136945lff.1.gmail; Wed, 16 Sep
 2020 00:03:28 -0700 (PDT)
X-Received: by 2002:a19:cc43:: with SMTP id c64mr7657235lfg.123.1600239808432;
        Wed, 16 Sep 2020 00:03:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600239808; cv=none;
        d=google.com; s=arc-20160816;
        b=g1lMLJCFUNK6JszZ1K1wMkQNBhJIUjrUDM/eQzftq6ZUke5cREcGt7zve6GMb4mChW
         7zmvq+4p22JIdCPSPD34KVqMxPAS6NfO9fo+bHMZaknVu/jYx0Ai9lz72V7HLzQCAsl9
         KKNaN94+CJXbB9RFkTf9cyEoXR0dznTlS/6JiqG0nXvwTuKTqHYnfkEWVT5DyqOlGrPa
         UwEHmENklAobZQcgO059Kx+oB7FVobrNskQ7nZ/qR6PHrX6R/pEPahhMcuiqpGvTq1jQ
         1zaG1ENT/SvJW+QZ+yQ+4J/E2OVaTJd6SHyVuULfFqa+ZfOVH3m1YodZTgvl107kJGU3
         CCiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=M12YDuTVvt+O6a6j14Ji1m8Yc8t57W8FWhVTEPcXPko=;
        b=0wHdxSaymmWnz+dVzAC8D5Xxc/qQ24LZZOIyfchU8pcYKo3WTVttGBz+KFtk104/eY
         MpUTPNqx9sRxpuqqdSfIDE4ZnBeQ8Eg5AHbW6GcA5oK+5edvW66ox4pr3rhsi+2JLcZ7
         URx2SIVL+P3RABfZrbYNzgWtcWvasKYpfsfpZc8HbXgju/Y33XSa6Wu68P5AqBI/MRtV
         V7wuQdO9w1myNa9O4EhZROHQ0c9t5aHR+0SuzUbRKDusEyf2MZ6Fl6goTWzMEOeuj7bE
         rKq901jA2mweZSA6J1UTsT4a4ElEKd5C3IAuwlxdwNnqQ0LxArjtqXg5bCRnOu4BS1qp
         Aj7w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=X+UdvNV0;
       spf=pass (google.com: domain of ilie.halip@gmail.com designates 2a00:1450:4864:20::144 as permitted sender) smtp.mailfrom=ilie.halip@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x144.google.com (mail-lf1-x144.google.com. [2a00:1450:4864:20::144])
        by gmr-mx.google.com with ESMTPS id h22si512448ljh.7.2020.09.16.00.03.28
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Sep 2020 00:03:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of ilie.halip@gmail.com designates 2a00:1450:4864:20::144 as permitted sender) client-ip=2a00:1450:4864:20::144;
Received: by mail-lf1-x144.google.com with SMTP id y2so5747586lfy.10;
        Wed, 16 Sep 2020 00:03:28 -0700 (PDT)
X-Received: by 2002:a19:189:: with SMTP id 131mr6663801lfb.331.1600239808160;
 Wed, 16 Sep 2020 00:03:28 -0700 (PDT)
MIME-Version: 1.0
References: <5f60c4e0.Ru0MTgSE9A7mqhpG%lkp@intel.com> <20200915135519.GJ14436@zn.tnic>
 <20200915141816.GC28738@shao2-debian> <20200915160554.GN14436@zn.tnic>
 <20200915170248.gcv54pvyckteyhk3@treble> <CAKwvOdnc8au10g8q8miab89j3tT8UhwnZOMAJdRgkXVrnkhwqQ@mail.gmail.com>
 <20200915204912.GA14436@zn.tnic> <20200915210231.ysaibtkeibdm4zps@treble> <CAKwvOdmptEpi8fiOyWUo=AiZJiX+Z+VHJOM2buLPrWsMTwLnyw@mail.gmail.com>
In-Reply-To: <CAKwvOdmptEpi8fiOyWUo=AiZJiX+Z+VHJOM2buLPrWsMTwLnyw@mail.gmail.com>
From: Ilie Halip <ilie.halip@gmail.com>
Date: Wed, 16 Sep 2020 10:03:16 +0300
Message-ID: <CAHFW8PS0WYdfO01XwmLa+3w2W-z_FF_a5eeF8Z-YfuCMQ15ccw@mail.gmail.com>
Subject: Re: [tip:x86/seves] BUILD SUCCESS WITH WARNING e6eb15c9ba3165698488ae5c34920eea20eaa38e
To: Nick Desaulniers <ndesaulniers@google.com>
Cc: Josh Poimboeuf <jpoimboe@redhat.com>, Marco Elver <elver@google.com>, 
	Borislav Petkov <bp@alien8.de>, Rong Chen <rong.a.chen@intel.com>, kernel test robot <lkp@intel.com>, 
	"Li, Philip" <philip.li@intel.com>, x86-ml <x86@kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ilie.halip@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=X+UdvNV0;       spf=pass
 (google.com: domain of ilie.halip@gmail.com designates 2a00:1450:4864:20::144
 as permitted sender) smtp.mailfrom=ilie.halip@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

> Should objtool be made aware of the config option and then not check
> traps after no-returns?
>
> I suspect the latter, but I'm not sure how feasible it is to
> implement.  Josh, Marco, do you have thoughts on the above?

This seems to do the trick.

diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index e034a8f24f46..9224e6565ba2 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -2612,9 +2612,10 @@ static bool is_ubsan_insn(struct instruction *insn)
                        "__ubsan_handle_builtin_unreachable"));
 }

-static bool ignore_unreachable_insn(struct instruction *insn)
+static bool ignore_unreachable_insn(struct objtool_file *file, struct
instruction *insn)
 {
        int i;
+       struct instruction *prev_insn;

        if (insn->ignore || insn->type == INSN_NOP)
                return true;
@@ -2640,7 +2641,8 @@ static bool ignore_unreachable_insn(struct
instruction *insn)
         * the UD2, which causes GCC's undefined trap logic to emit another UD2
         * (or occasionally a JMP to UD2).
         */
-       if (list_prev_entry(insn, list)->dead_end &&
+       prev_insn = list_prev_entry(insn, list);
+       if ((prev_insn->dead_end || dead_end_function(file,
prev_insn->call_dest)) &&
            (insn->type == INSN_BUG ||
             (insn->type == INSN_JUMP_UNCONDITIONAL &&
              insn->jump_dest && insn->jump_dest->type == INSN_BUG)))
@@ -2767,7 +2769,7 @@ static int
validate_reachable_instructions(struct objtool_file *file)
                return 0;

        for_each_insn(file, insn) {
-               if (insn->visited || ignore_unreachable_insn(insn))
+               if (insn->visited || ignore_unreachable_insn(file, insn))
                        continue;

                WARN_FUNC("unreachable instruction", insn->sec, insn->offset);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHFW8PS0WYdfO01XwmLa%2B3w2W-z_FF_a5eeF8Z-YfuCMQ15ccw%40mail.gmail.com.

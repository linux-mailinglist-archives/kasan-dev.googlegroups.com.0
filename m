Return-Path: <kasan-dev+bncBDW2JDUY5AORBGXN5XCAMGQEF3ZKBKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id DFCBBB22EBA
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 19:15:07 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-55b8085bdabsf2807560e87.3
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 10:15:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755018907; cv=pass;
        d=google.com; s=arc-20240605;
        b=D4jV81hrtd9f7kkpJo0j/lFUZQ6dQNovYROxoiF97TvsrTZvFDyrJ33iy7h51Urzyq
         kTcd1slh9Ih7X7UUcQDQK2xQNIvuGKGklM9YABZurzYUNoS795StMiRLhXrwkjMSFK+r
         ZV3IUmp3mxuysIgkjxeyMAZtG9miBjxbPOW7+b+1OWGyndrVeN/25g+NCXtLs+nC/Ofo
         tWM9cAnJfJyg61GkYi5NOItvOjJSaLUD+njgUgzkHY887HT7AEJEflbWeTdCjWpesD8U
         wl8dID2i4LlULLwc1s2sYFXLiGineENPhogP25+rpXpM8kXOLmmGmJJ5q/VA7os5Po3r
         JDGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=3bRB4Fab0wilAqhvO2DkfC4OMaNB4szpaMky80GaifA=;
        fh=OYfMLOeAs+5gED1BfVP+L48eAOqDygyorwarJ2+YEaw=;
        b=frRSYQedIJsn+z9Ylpx3Yt5PqNcMMe0irWfpEzUeX2tZdF+IqLPA/qUG48v02/9v+7
         RDHe4YElVB5Vpa7zx40+0RPs2Qh5YAiSXtL27bavDoayw//hQ9nLRcKACYaW1x+lX9wd
         kFFQC3x81n1IuNc8oNzJ2SeJSdi+8YZgEQaXGz9oDJIePcG9v9Zt84N7XdOL4Qyo0jpS
         Rs21TcTt5XpzI/jssN24Eewoq71fPdGao/nn9o3hmS4DKc1+qEfnnEBXpvbDU7f9qcF2
         HwqI3V7LtPSgQCCIafbEna7cKbnNubPPbax2evFWmMPnUS55D8ESPz/Z5CmU0LMwHGxT
         9OxA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=V1wIwjhR;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755018907; x=1755623707; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=3bRB4Fab0wilAqhvO2DkfC4OMaNB4szpaMky80GaifA=;
        b=cd0mhAnLvzXbdVkYtmpNPfQ6/hdBNBcemKrPXYQ/B9UfTWQ6dwKZxBmbSwMF6EPW5B
         KcpLDHyyoLZnlwa6yidttRl/C5i2oDAJgpIQEy0y4bZHeNSb++dGkBRmyT5HWCsZkiBc
         XIsCQd3vbzwWonj3EqFtjTpLQXjZIbhMuFmSw/YoRhbys9guwJ56GOe0TS3VSy8Nt4xs
         Z5iTXT3lUurV1vyDlMdLTiS9oWbmRW0rNNMGByV9y8g8a1652Iznapi/QRmnfVZquBRK
         kMhlwne1x8tBUrMi+zAz0GGD4s1BhqWVMImBChZuZG0ojNirR2dYRkmjwfcYP/1vdOlh
         4wVw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1755018907; x=1755623707; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3bRB4Fab0wilAqhvO2DkfC4OMaNB4szpaMky80GaifA=;
        b=YEzZ4KcqViXP7sB4tUK6UC1gU0kQxHr29F5NzMGJe3qtoy/MrsScDoJ8pMqzKDf2BU
         1YqlMkwdQ5OqpsGMoeU3WpYlZ7+1nTYPuwkWnqvejD6th1N89nkzFgghHvz7o2eSgWW7
         5cfjxh8N7cc5PbJ04vAPEAOykBtmPGb3unc5j6iRUK/ynHk9tsX/ZcPp667PgpeFN+AU
         heMgmAMk+8g0apMZuloN7VrcuIgIn6898qwp9DUk9SdoIgGWrI3bMI6dhfpajFpxYhCo
         HiJQRv/dqSHXCVBhDzOMjFnEXQ6aBByrXLmN5MYicnkBOiTmw5pMa/0M++z87i1U6Ajo
         kmTQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755018907; x=1755623707;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=3bRB4Fab0wilAqhvO2DkfC4OMaNB4szpaMky80GaifA=;
        b=IjXl/DR3WaYV0oPOMZW1SOpWZAY39LqXI5IG3zhAayYv8tuCRkJZnsLIxixI0bw4tZ
         KyuveCnoh9XB7l/LtAM/uhfrhu8inygAKuBXuGA/WKWBNW01cjJxWmbQc2TUxHTfhc5h
         LM0twBWnxoelHEUidjWvOMB5xVEjeOdbVUUwqpEs9cxOx45z1droMecQHc9pHaoP32Eh
         5LMI0RXpvZqhUu/1VJfZwBSS3/tJCOukIg3L7EARkEZn3ttCg6A/GDZfflrkJuuFclgV
         MsEFTdmOl2nH3AMnFv0GPu9ooCxHvlZ7FnBgW0RTyv5vXbVVpgfcoSyHMYt5nOWLcwhG
         JNAA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXABhzYSThelPWL1xkPYCmCqIsA1uWEaExMlb0FCCeDGiaOQiJxGXEzmvHOkF+4bVtA9drofg==@lfdr.de
X-Gm-Message-State: AOJu0Yz8+YHqO7MMztQ353F/+LV2TcwJEe1CyedXaX8ryehFOPS2+oSM
	fp9SDQ8gyn8TBMXSMgeYeWAwwQmai1+dKIK+E7oeMxKeAd0sJG/9qcbv
X-Google-Smtp-Source: AGHT+IHnQhjeWivteUV/9dg6jSG8UPatSgB4qTO0t3tUV8Q5AS1pS2h0Jw7Q1I+5pvcOHHszsUxjYw==
X-Received: by 2002:a05:6512:1392:b0:55a:4e55:cb94 with SMTP id 2adb3069b0e04-55ce0149544mr18728e87.8.1755018906908;
        Tue, 12 Aug 2025 10:15:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdGVTGvDan0ypNVGwPxf2ubHV8oX3evVOBHFFnVm4xNTg==
Received: by 2002:ac2:4c4a:0:b0:55c:d705:e00d with SMTP id 2adb3069b0e04-55cd705e2c2ls484636e87.1.-pod-prod-06-eu;
 Tue, 12 Aug 2025 10:15:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWJo3Jk1P3hQ9AGZzYcyowuYKcwnYSL6LIFu79u3S1XzaWNaFTxLMRBTai8oMIjy/E4tunlwLK+spc=@googlegroups.com
X-Received: by 2002:a05:6512:4002:b0:553:2480:2309 with SMTP id 2adb3069b0e04-55ce0149677mr23760e87.3.1755018904138;
        Tue, 12 Aug 2025 10:15:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755018904; cv=none;
        d=google.com; s=arc-20240605;
        b=XWwkpQOx7WOgTIc0jbLDFwmN/zVasy/5XMljpNmBxYV4eWKTPfTYPTH/YdsF89cJFA
         uqHm9UBmwku1p/Uc8yOVTeo1zFjbqpyYg4W6JBaSImTtccgVnjTHEInUWAU0Eds5I5ub
         HOp+JA/IAefMT0KA7pgwBaKVv27ErxU+ExLXDZq0R7Gwrww7gR4MpvKnbb3ZEr7u/2Y1
         py1bRAv1QufohSEC0VFuZxEOyFY/2ujxr/grq0Z8CoTPer3OT/DI2qgYrpu7tOfAQryc
         b5Hh7K5Hibsuar3zGabPTtF0o8syuVyHWKEuxnEU2Uaf0rEOyO/5kuCuCuvTZ4KvXn1Z
         +diA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=emH/9/qIpMML7VwyXCdOqP+butuG+Y1J3ry+obz5qAU=;
        fh=BPvmmQl0X7dcKmtcx85PqGnknVyS2BEXtrHIEj45kIs=;
        b=Q9bbnLWNBpAOZxt488pNDW4hCAH8xleBLK3lhFECnlnaKt4Lx/4kTUWzBvl6lodlEJ
         2SksV+Y1lLuJ63Q10gEOTVLl+t9sSwvxiMPSaVbQWpB6IY//Xpao3yiD3eShn1Hi87Ch
         uVmXtgtaGI4qwhIeIR+QJOFmNqFZUo71DIRhThHJ8wQI+hbTpudRmZ18rRrY7JA2RJIS
         Csm/pW9okSs+QMF8t3Bog67x4yniLhHme3gCBFe3lFLto64Su4/jEyrb6JwMeBrfdSfK
         kjIjFkO17slHFfEaGA21MDUL3oCS53jNwip3GS2wU6lCEU+tdeOg1WNhhgcMofrcGOEr
         YGrQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=V1wIwjhR;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42c.google.com (mail-wr1-x42c.google.com. [2a00:1450:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55b88970321si673712e87.8.2025.08.12.10.15.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Aug 2025 10:15:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) client-ip=2a00:1450:4864:20::42c;
Received: by mail-wr1-x42c.google.com with SMTP id ffacd0b85a97d-3b8de6f7556so3201344f8f.1
        for <kasan-dev@googlegroups.com>; Tue, 12 Aug 2025 10:15:04 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVcgckVRvQ0E8I+nADf/OaWo+zCVrbQTfaFIdF7G+cI0xLYirQppkEWxVC4Ehcpunu/9DLeypZICpY=@googlegroups.com
X-Gm-Gg: ASbGncs1acF+1PjORftYBGJyKggwn/Nr49FPbiE0DOLjl6Eav5S5mQAev/MHF+T9FW+
	ehgPNs2nb6paJ57pDgDKN9FdiE3/JAaD5/JtDHXCr+EZhYk8WIdaw45nyttgiwwtFSf2z7B4Sa+
	ygSPPac/HxlrJAZWJV6hzxtsKlXGjHwuatTez9XIY8xaYfmeZfXimAjTtwYoHmJrUavB4H1FeWL
	zGNs1x1Pw==
X-Received: by 2002:a05:6000:2386:b0:3b7:7489:3ddb with SMTP id
 ffacd0b85a97d-3b91730553amr137411f8f.34.1755018903312; Tue, 12 Aug 2025
 10:15:03 -0700 (PDT)
MIME-Version: 1.0
References: <20250812124941.69508-1-bhe@redhat.com> <CA+fCnZcAa62uXqnUwxFmDYh1xPqKBOQqOT55kU8iY_pgQg2+NA@mail.gmail.com>
In-Reply-To: <CA+fCnZcAa62uXqnUwxFmDYh1xPqKBOQqOT55kU8iY_pgQg2+NA@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 12 Aug 2025 19:14:52 +0200
X-Gm-Features: Ac12FXxbfIp4CjdMiDbk99JZKDZitEGnh3AeOJx4PqX8F5dQQ1jZuZRm61N9EdU
Message-ID: <CA+fCnZdKy-AQr+L3w=gfaw9EnFvKd0Gz4LtAZciYDP_SiWrL2A@mail.gmail.com>
Subject: Re: [PATCH v2 00/12] mm/kasan: make kasan=on|off work for all three modes
To: Baoquan He <bhe@redhat.com>
Cc: linux-mm@kvack.org, ryabinin.a.a@gmail.com, glider@google.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	kexec@lists.infradead.org, sj@kernel.org, lorenzo.stoakes@oracle.com, 
	elver@google.com, snovitoll@gmail.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=V1wIwjhR;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42c
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

On Tue, Aug 12, 2025 at 6:57=E2=80=AFPM Andrey Konovalov <andreyknvl@gmail.=
com> wrote:
>
> On Tue, Aug 12, 2025 at 2:49=E2=80=AFPM Baoquan He <bhe@redhat.com> wrote=
:
> >
> > Currently only hw_tags mode of kasan can be enabled or disabled with
> > kernel parameter kasan=3Don|off for built kernel. For kasan generic and
> > sw_tags mode, there's no way to disable them once kernel is built.
> > This is not convenient sometime, e.g in system kdump is configured.
> > When the 1st kernel has KASAN enabled and crash triggered to switch to
> > kdump kernel, the generic or sw_tags mode will cost much extra memory
> > for kasan shadow while in fact it's meaningless to have kasan in kdump
> > kernel.
> >
> > So this patchset moves the kasan=3Don|off out of hw_tags scope and into
> > common code to make it visible in generic and sw_tags mode too. Then we
> > can add kasan=3Doff in kdump kernel to reduce the unneeded meomry cost =
for
> > kasan.
>
> Hi Baoquan,
>
> Could you clarify what are you trying to achieve by disabling
> Generic/SW_TAGS KASAN via command-line? Do you want not to see any
> KASAN reports produced? Or gain back the performance?
>
> Because for the no reports goal, it would be much easier to add a
> command-line parameter to silent the reports.
>
> And the performance goal can only be partially achieved, as you cannot
> remove the compiler instrumentation without rebuilding the kernel.
> (What are the boot times for KASAN_GENERIC=3Dn vs KASAN_GENERIC=3Dy +
> kasan=3Doff vs KASAN_GENERIC=3Dy btw?)
>
> Thank you!

Ah, you don't want the shadow memory for kdump, sorry, I somehow missed tha=
t.

I'm not familiar with the internals of kdump, but would it be
possible/reasonable to teach kdump to ignore the KASAN shadow region?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZdKy-AQr%2BL3w%3Dgfaw9EnFvKd0Gz4LtAZciYDP_SiWrL2A%40mail.gmail.com.

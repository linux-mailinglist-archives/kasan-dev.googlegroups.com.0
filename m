Return-Path: <kasan-dev+bncBCCMH5WKTMGRBCPMZOQAMGQESRERE3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 970696BCD59
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 11:57:14 +0100 (CET)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-172ace24d4dsf970161fac.18
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 03:57:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678964233; cv=pass;
        d=google.com; s=arc-20160816;
        b=cB9nGTQAESRY6mRpFu4yPqaMro6FjMA0tG/Fr8wZUy3T1E9E3DS9GPjr7M1HY7bpy8
         oXz4Y48qkZ4uEYuF4qbV5BnIvJEKrmq8h4SDUIaSp0kmWxAh3LdsH5ezpAx7lKgnNqih
         /XFNMnoIFs2AmWm8Q3/b+pqar+zf3Sr0VA7IzYxMIAowaizNCKJoOKpioPgtvaJe3L1e
         CKmDTYQb8eFmAUrl3XR8Dw5MeNltsqDoqxhhAJTBmNtcEEJF4Y7s7zNSCjd5XTAeVltz
         XLY50t4DcnVA8xWUwsZuWL7ve++TtGEFoZrxtiSYvZFk10TTtjk7ZSAZJUXxIEUPkv91
         PFQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=THCHgQKXWPspxw9rMHKdRLKdnRxxkkfgM3Znm3VnjtM=;
        b=b7mrZTTV6KQ/FFjGhc1ZEAOqxBTUMhFVQ1bMr25VbN+JFodwAHRqoP3Uun+6XYKZUG
         KO4azjc62j29mGhrN+6CxLyXsV5VCHVdDUQv7uo0B1PyAirTC+1yurQOG1YAfjXgyol3
         AGfDzCkQRYcX+iu/xQxw7yYAMR60DF7ezKhj31tU3rq6Rzl1AnXBBpttJ5qCrr9Flm3E
         yUnozHsVoo1MwUpmT1ZipnEWcezmFEn2RIUX/5ZfXLGCvlLIQPRFwTQeSkokFZOPxhS8
         YThWOnhEUIId4g2H0u7XyJ59O2qI/VF2qJCenzlSbvCO5VJlZQqb7st8j9ZqqnuI2lpg
         F3+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=EsQa39u7;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678964233;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=THCHgQKXWPspxw9rMHKdRLKdnRxxkkfgM3Znm3VnjtM=;
        b=L7b61FZidfDy3HcHgfZ/g7BJZwf7P51BXkTKirCSgM2ZJoHb6Rt9cQ7s/mxK8neU4a
         SSz7sVdRyDX+/eW2KSIce4Am49E1HO0b2GcfzS279iCnvstmcqeYR0H4dJsB7WvE8RYt
         TtXcbw5CYJaZtltlgvEWnifWhAU/TQtqh8/LB5UHGCfukQ1gXnYGi5zwl2BDn2tzYeZV
         LQxMjrOCmXBaVbB8ud3mgJqfMUCkC3jYXJuhKn9pvzQSUX+JTaPBWRYXw04QQ3boHgHX
         Ow/6ISYduvXkCYXCiecSD1u+3BNbWcK9F0IwErK+svYOo/5v7/bls42CXde7SV52P0iy
         u+ig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678964233;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=THCHgQKXWPspxw9rMHKdRLKdnRxxkkfgM3Znm3VnjtM=;
        b=C7AA767IUSyG2mG5sY77hEn8Xnw6k3R9A/h+ijVBa2AVG3Za3GXgXARO4tKMmyN9dZ
         hRjAN7mm5lAEBuTWQBayy680CGqHsMQFmWMPwkZmTetTX7OGvOYEr+k0HR01z7jug3rL
         Zm0yLzRp6zSBN5ESlQFXKfJDTVhkd4LbTUjnUaQYiO9m6IMUsynt4WV7ao7b55JclF99
         mRKmF9Nn787IwCmJiiI2x5DLCUfHFJLC4fEXV0IUod7tx0AKmxaZ5U4qnlwlFPUVdT6a
         NEDhjqZigTxZthRuTI+2NWxEU/OB5XMEqgndORkzlaD70thihfG/KuKVlMcYQdV+neWp
         8C7w==
X-Gm-Message-State: AO0yUKUqB9Ikdz85U3Hyc7DJoB7ssD+XAHaWk1dIdJKys+GNh0DC+Alm
	tMeewbSXToODFw8JJRXp+vE=
X-Google-Smtp-Source: AK7set9R9GYWYlKbw5c5C7bAWPU/Jaudz49AqYUutU4Pl0WVNL580Ad18RhwxeJ4UpDVUpusa4zccA==
X-Received: by 2002:a05:6808:6385:b0:384:21dd:2793 with SMTP id ec5-20020a056808638500b0038421dd2793mr1733904oib.0.1678964233124;
        Thu, 16 Mar 2023 03:57:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6053:0:b0:690:d969:257b with SMTP id v19-20020a9d6053000000b00690d969257bls228392otj.4.-pod-prod-gmail;
 Thu, 16 Mar 2023 03:57:12 -0700 (PDT)
X-Received: by 2002:a9d:354:0:b0:698:2905:38e6 with SMTP id 78-20020a9d0354000000b00698290538e6mr4218908otv.1.1678964232549;
        Thu, 16 Mar 2023 03:57:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678964232; cv=none;
        d=google.com; s=arc-20160816;
        b=ZWzv1Tkb5YhbHDmEs18I3ACA7sY9eG833OuSxSHTCQu3pndH/qnkS/lkYYOMOHOnhG
         BtgHim7MPyYDqqMsJxfpLz4N+JrJ0ccfymo/+Lo/96csQspnP8Wf7TMmb1y7Cq/Km9an
         WLUpIKBLGX22eqeVnBn6u1aF9SOPWC0GkAGAHgnkbWXv3z0ExZbSWVXLiD2o4J2se8Lb
         I4KVNX1IPw0CpsWChP0G35XMZ6hbvV8Ufl52hpYTVU1/gkwXFwfTK3Hxe349YONi+sjX
         yITDJy0CmgqfdFkpN+GGlUlaPvkHy/OqHUyEa9xaqMM0D2IlHPh416UF9njwb1sE/5AS
         XT6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=u/T0qKic4XkfUhsmQWQSF9or/BRDzsjc5j/nv/2Gg40=;
        b=H6KvmLtiPu9HJPUUbrgMpARlLAIFiYSgHeGLo6XV+L4JNVdgUuS4ymX7ZIWTmRZgwB
         FSMUIUnb2zqAn1kU3/zgGzw+z6uTUHKkS6FMPLtn0dwEnqwGdYdjIIkNHbsxA7iyiAzW
         d+svK7AqTt3xfPfN8v+pBHFmgKIOE17qXsjVqfJct6ZzvpUPPwGSSwaLIkNScWiSubbd
         wBDfk9QrcUc6GzaIz5nYDp6/89IgMMe84ANhWjhLwGxfO94MP8MYh+LpXpeq39quFrfN
         EAK/sG6GW5Llfj6kb2mKb9zA0te+l/mBZChoGbyDm3l2KcmTr6LwYOgXB4OjRl3jfmxL
         mnKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=EsQa39u7;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd33.google.com (mail-io1-xd33.google.com. [2607:f8b0:4864:20::d33])
        by gmr-mx.google.com with ESMTPS id g24-20020a4adc98000000b00525240a102asi462479oou.1.2023.03.16.03.57.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Mar 2023 03:57:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d33 as permitted sender) client-ip=2607:f8b0:4864:20::d33;
Received: by mail-io1-xd33.google.com with SMTP id h83so571239iof.8
        for <kasan-dev@googlegroups.com>; Thu, 16 Mar 2023 03:57:12 -0700 (PDT)
X-Received: by 2002:a5d:8897:0:b0:71b:5cd7:fcd9 with SMTP id
 d23-20020a5d8897000000b0071b5cd7fcd9mr26589709ioo.20.1678964232048; Thu, 16
 Mar 2023 03:57:12 -0700 (PDT)
MIME-Version: 1.0
References: <1678956620-26103-1-git-send-email-quic_zhenhuah@quicinc.com>
 <20230316095812.GA1695912@hu-pkondeti-hyd.qualcomm.com> <e363fd76-67fb-5a0f-5ef9-59d55aa2f447@quicinc.com>
In-Reply-To: <e363fd76-67fb-5a0f-5ef9-59d55aa2f447@quicinc.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Mar 2023 11:56:35 +0100
Message-ID: <CAG_fn=UigFQX8ZrNPoAFfXiV-JCP5ZyrtkD0TUNPJcN5-99VtA@mail.gmail.com>
Subject: Re: [PATCH v9] mm,kfence: decouple kfence from page granularity
 mapping judgement
To: Zhenhua Huang <quic_zhenhuah@quicinc.com>
Cc: Pavan Kondeti <quic_pkondeti@quicinc.com>, catalin.marinas@arm.com, will@kernel.org, 
	elver@google.com, dvyukov@google.com, akpm@linux-foundation.org, 
	robin.murphy@arm.com, mark.rutland@arm.com, jianyong.wu@arm.com, 
	james.morse@arm.com, wangkefeng.wang@huawei.com, 
	linux-arm-kernel@lists.infradead.org, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, quic_guptap@quicinc.com, quic_tingweiz@quicinc.com
Content-Type: multipart/alternative; boundary="000000000000a4ca1005f70252dc"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=EsQa39u7;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d33 as
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

--000000000000a4ca1005f70252dc
Content-Type: text/plain; charset="UTF-8"

>
>
>
> >> +    /* Kfence pool needs page-level mapping */
> >> +    if (early_kfence_pool) {
> >> +            __map_memblock(pgdp, early_kfence_pool,
> >> +                    early_kfence_pool + KFENCE_POOL_SIZE,
> >> +                    pgprot_tagged(PAGE_KERNEL),
> >> +                    NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS);
> >> +            memblock_clear_nomap(early_kfence_pool, KFENCE_POOL_SIZE);
> >> +            /* kfence_pool really mapped now */
> >> +            kfence_set_pool(early_kfence_pool);
> >> +    }
> >
> > Why not wrap this under CONFIG_KFENCE ? early_kfence_pool can also go in
> > there?
>
> Because I didn't want to add CONFIG_KFENCE in function.. in the case of
> w/o CONFIG_KFENCE, early_kfence_pool should be always NULL.
>
> Please no. If the code is not used in non-KFENCE build, it should not be
compiled. Same holds for the variables that only exist in KFENCE builds.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DUigFQX8ZrNPoAFfXiV-JCP5ZyrtkD0TUNPJcN5-99VtA%40mail.gmail.com.

--000000000000a4ca1005f70252dc
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div class=3D"gmail_quote"><blockquote class=3D"gmail_quot=
e" style=3D"margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204)=
;padding-left:1ex"><br><br>
&gt;&gt; +=C2=A0 =C2=A0 /* Kfence pool needs page-level mapping */<br>
&gt;&gt; +=C2=A0 =C2=A0 if (early_kfence_pool) {<br>
&gt;&gt; +=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 __map_memblock(pgdp, ea=
rly_kfence_pool,<br>
&gt;&gt; +=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 early_kfence_pool + KFENCE_POOL_SIZE,<br>
&gt;&gt; +=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 pgprot_tagged(PAGE_KERNEL),<br>
&gt;&gt; +=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 NO_BLOCK_MAPPINGS | NO_CONT_MAPPINGS);<br>
&gt;&gt; +=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 memblock_clear_nomap(ea=
rly_kfence_pool, KFENCE_POOL_SIZE);<br>
&gt;&gt; +=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 /* kfence_pool really m=
apped now */<br>
&gt;&gt; +=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 kfence_set_pool(early_k=
fence_pool);<br>
&gt;&gt; +=C2=A0 =C2=A0 }<br>
&gt; <br>
&gt; Why not wrap this under CONFIG_KFENCE ? early_kfence_pool can also go =
in<br>
&gt; there?<br>
<br>
Because I didn&#39;t want to add CONFIG_KFENCE in function.. in the case of=
 <br>
w/o CONFIG_KFENCE, early_kfence_pool should be always NULL.<br>
<br></blockquote><div>Please no. If the code is not used in non-KFENCE buil=
d, it should not be compiled. Same holds for the variables that only exist =
in KFENCE builds.</div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAG_fn%3DUigFQX8ZrNPoAFfXiV-JCP5ZyrtkD0TUNPJcN5-99VtA%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CAG_fn%3DUigFQX8ZrNPoAFfXiV-JCP5ZyrtkD0TUNPJcN5-9=
9VtA%40mail.gmail.com</a>.<br />

--000000000000a4ca1005f70252dc--

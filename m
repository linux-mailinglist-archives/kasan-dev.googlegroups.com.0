Return-Path: <kasan-dev+bncBDE6RCFOWIARBD5JQW4QMGQEU3MWRDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0EAFD9B5519
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Oct 2024 22:33:05 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-2fb58d1da8esf33993501fa.0
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Oct 2024 14:33:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1730237584; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ceu8ytg1aYFi+fckEJSdkZwfhHHczBKWmrDOYP0ejozEv+tW/FS2/yCMVAF9Pv8chv
         yvnLqq8kbW77S9rJtdlj1eCeOrBbn3zJlYwx3TnDX4NjI8se9u9q0DR0VWMRXbS+3R3h
         ySw/MBmq5Y28TExszr7r3mzbQ9C7vMFEkANR/L+7JCorlYuEpmdn2CHBHnrVJSIdSCv+
         JEnTg7Em5xbf9AtS6Nj7EsVRe7uIfjtwExUYqs/duwZ0163tuSEoVEtPHpqOpskTwKCv
         U/mQdPg+MQDPxgvGUIZcv0SG/9YKBCBynBj3rWQIovdcdVV0HXb7ej/wY5KWludBFFTB
         rp7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=DFTpd12c5x6iWz03aTZB54f+WikbRKLG7BNsJrICOIo=;
        fh=FxoBKSsc1OrJ28cmlt5MPkeP5OSOW5Wd0FcMM81D74I=;
        b=Un8dbctQkcnoVuoOyzIfi5t2l9+E2POcSXChwfpHEZ0NWb3tUo/a3ReQA7Q2sGBjtw
         Ov8nRTIzqTgwKeOJo+Ul+ruCe1FZiThsvcrGfyJydsvx5GDz9QbsyEIQF5DtCE1QVvke
         1SEAvpuHnYHYTjp/TMfTnh5S7khOIUSnQE3JihOiC8T0DlTwAMLykeHOmo+1IG4Feoyn
         6/5jJzs+mtrUNVKquJ+cYZeV8uBPkbpj5IbcPFGbc/Jq3hS4yqyc1CBdRXxqMbHg7k8F
         4UZohnHGaujNIDCOIk5b3rvj5p2v1kYnyGjLhFNkdbVkEeEeTTD0ceOPsxDXZmlLGo6X
         KuuQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=i1eNNraK;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::22b as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730237584; x=1730842384; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=DFTpd12c5x6iWz03aTZB54f+WikbRKLG7BNsJrICOIo=;
        b=MiGb9l7u2JbTSXo+KdL0mlO4u48p6CqKTRqBa9V+1I2MNiOJujJUVEI+iPQN+tc9qV
         +NfbA+ub55tGYfEZwNWakLsqi5U82P3pr+CL9kwNDBqyPJEteZnVqjm1FnmAXtuJq6/U
         PGpFUH6GUBgdDrPkVujgJFisGz+YrrzmGiHf0l81Hu/1I4zmfMHcz77MUuG9bchVCzZI
         sdW6ZSZ6Gf5Mt5KJhmvBPQPM5amYjPQNafZfVvEo/oJS8/KiR+0OMUpY7leeHrU1G3Tf
         vW6QJ/C4Mjm4YUDW4XA9AZk0HykzIALNQkAp4kFjCGbiJ1z8Bw1eCe+5OvYtV+HoaRjI
         kdHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730237584; x=1730842384;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=DFTpd12c5x6iWz03aTZB54f+WikbRKLG7BNsJrICOIo=;
        b=TXUAcRdg5HSg1bWlLpsk9rGkzu+cFS1m0VswAecHaPhN42iYXcU0c2wOYu/fTnVZj1
         reb+u0ryYSQiJtAri7uutTD8ttQbsnlfMH4PmvWwmU1j2LtW+w/idUo5HVyXBzfJymwU
         zz4r9ZBSoqLIYdkWIyQV/i/c1DMtHtH5MmTlCdlIVnRKbYkyQ+Vgcmi0a4/X+jvTqlfB
         iQwQpnGW1Ga7jFlyh/5E5Jr6zG6Bw66kBuniX3523rTrRKt8J/Zjb6lUqXqjndeprb4b
         fWZ9g9G3sR8SeI3w+RfRq3kykqDxMV98JxcKBnQBW4zZogjakAK8naK5itx2lz5lfKCP
         EJsw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVXC+FhwsEqN3Y5oqQRNsA75U5tweXKAjMtj+IpLphBviXnVYOR4xu57SYdFDrj2f87laAnLw==@lfdr.de
X-Gm-Message-State: AOJu0Yz79FM4Ket4aHLA3cN8GtukfTlEbIKeO4GQ67V97iC2uPfPiIr7
	a5jcxeNrhX/xiFGh0FFVNXO/YSXefsgQ8NvyOMbvXc6Y6Fe1qBCa
X-Google-Smtp-Source: AGHT+IED8xRZCRjzNi0a2aI6lMUV0sKIgxmDlb1dEvAeTA0jvzXVWTkDyfUno/NQ3rNLwItUvwpLsA==
X-Received: by 2002:a2e:b817:0:b0:2fb:2f7c:28e0 with SMTP id 38308e7fff4ca-2fcbdfd4ca7mr49128741fa.18.1730237583604;
        Tue, 29 Oct 2024 14:33:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2a04:0:b0:2fb:358c:f76b with SMTP id 38308e7fff4ca-2fca5966468ls6894851fa.2.-pod-prod-06-eu;
 Tue, 29 Oct 2024 14:33:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVM0ADYvOw+lZCSxY2HE7i0HQXtq84z1b6NOkYafq1OzHgnqR1B9qbkHn4E2YnndVF5+eM4XZwDHL0=@googlegroups.com
X-Received: by 2002:a2e:be04:0:b0:2fa:ce87:b7ea with SMTP id 38308e7fff4ca-2fcbddfeb5emr62087341fa.0.1730237581500;
        Tue, 29 Oct 2024 14:33:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730237581; cv=none;
        d=google.com; s=arc-20240605;
        b=HnqIQvfCDKB3KCRmHo0fRmLcisM7p9+u1exxP4/XF60x1R0dEagKLZf9uHWu03prJT
         jtHh5wy842vZMayzCsGQZpbwgBu6iRn25h0VfS9/vuYRFlwmFG1WigPrnh19gr7q5NLa
         uYvQILScrzfEMf+Rf4S1q4dfJopyu8s0K8WegzXO3evgovXnPn0NhBddaESH2V2xbhTO
         Ppwa7Km+MGTuU0EqOwV8D3xVAe2gZYYqicCg9WUt3xjFHrwooHQG1+xlG2fct3K4ciVu
         Whg6O/VtJObjjnzRyg3gIkxu5BIjN6a74jZDEYoilq0VgSk5XDBKUvGyrCvfr5h5dGF4
         2XHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=q8g0feFRM/g+KnXJgAODk2AAUgWx4QsqawCDf5AlE04=;
        fh=KCR4dcW9r3iBUR7oD2/KM/+1QyLPII1h9QoseRj88ZM=;
        b=jIVU8HX3xVP4EZnH1bhO7V/fFj+biL3PQf4s6hCWJW9WazaI6I1P5gMRiUxGDhBXz7
         guUmy0l9s7NWtzOW8n7PePChi6T0Dv8PAeLRaZsBzas0HtFd6kkUQj+ct1Hj3jZHiF+n
         edyDizF04S1GNzHEEChX27c0O9uYNxl5l5STNKT7gtRX1IzzMxt8Gd6JsWIxMSftRunb
         qHq1BzXD064uq16XrqZS2MrcfEt3jhvOopMDXq1e+ZzrPX+DYCI12UkwwuKIVkqTypKu
         JWa+69RX44WWdWJdADnPgdxlANOp1deaAAC9JVPG9K35PUw/7n1SAfvrdZX2xomR0BQU
         yGhg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=i1eNNraK;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::22b as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22b.google.com (mail-lj1-x22b.google.com. [2a00:1450:4864:20::22b])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2fd535d10a6si95141fa.5.2024.10.29.14.33.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Oct 2024 14:33:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::22b as permitted sender) client-ip=2a00:1450:4864:20::22b;
Received: by mail-lj1-x22b.google.com with SMTP id 38308e7fff4ca-2fb3da341c9so58655091fa.2
        for <kasan-dev@googlegroups.com>; Tue, 29 Oct 2024 14:33:01 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXt9IjhO2dmRLStvE6gNiBIdGAf0fG5WkvH5aIYh/72Z0ywPhXjpQ8oyq2Tr4Y9LtbvgCJL66CsnVM=@googlegroups.com
X-Received: by 2002:a2e:be9f:0:b0:2fb:3bef:6233 with SMTP id
 38308e7fff4ca-2fcbe08cf3bmr60977061fa.33.1730237580772; Tue, 29 Oct 2024
 14:33:00 -0700 (PDT)
MIME-Version: 1.0
References: <20241017-arm-kasan-vmalloc-crash-v3-0-d2a34cd5b663@linaro.org>
 <20241017-arm-kasan-vmalloc-crash-v3-1-d2a34cd5b663@linaro.org>
 <69f71ac8-4ba6-46ed-b2ab-e575dcada47b@foss.st.com> <CACRpkdYvgZj1R4gAmzFhf4GmFOxZXhpHVTOio+hVP52OBAJP0A@mail.gmail.com>
 <46336aba-e7dd-49dd-aa1c-c5f765006e3c@foss.st.com> <CACRpkdY2=qdY_0GA1gB03yHODPEvxum+4YBjzsXRVnhLaf++6Q@mail.gmail.com>
 <f3856158-10e6-4ee8-b4d5-b7f2fe6d1097@foss.st.com> <CACRpkdZa5x6NvUg0kU6F0+HaFhKhVswvK2WaaCSBx3-JCVFcag@mail.gmail.com>
 <CACRpkdYtG3ObRCghte2D0UgeZxkOC6oEUg39uRs+Z0nXiPhUTA@mail.gmail.com> <aeef0000-2b08-4fd5-b834-0ead5c122223@foss.st.com>
In-Reply-To: <aeef0000-2b08-4fd5-b834-0ead5c122223@foss.st.com>
From: Linus Walleij <linus.walleij@linaro.org>
Date: Tue, 29 Oct 2024 22:32:49 +0100
Message-ID: <CACRpkdbgZ2J_-9KLeRz2Y8G4+T2qPo5uax4-o=KZbVFRVEO4Hw@mail.gmail.com>
Subject: Re: [PATCH v3 1/2] ARM: ioremap: Sync PGDs for VMALLOC shadow
To: Clement LE GOFFIC <clement.legoffic@foss.st.com>
Cc: Ard Biesheuvel <ardb@kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Russell King <linux@armlinux.org.uk>, 
	Kees Cook <kees@kernel.org>, 
	AngeloGioacchino Del Regno <angelogioacchino.delregno@collabora.com>, Mark Brown <broonie@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Antonio Borneo <antonio.borneo@foss.st.com>, 
	linux-stm32@st-md-mailman.stormreply.com, 
	linux-arm-kernel@lists.infradead.org, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=i1eNNraK;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::22b as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org;
       dara=pass header.i=@googlegroups.com
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

On Tue, Oct 29, 2024 at 4:03=E2=80=AFPM Clement LE GOFFIC
<clement.legoffic@foss.st.com> wrote:

> I have tested your patches against few kernel versions without
> reproducing the issue.
> - b6506981f880^
> - v6.6.48
> - v6.12-rc4
> I didn't touch to CONFIG_VMAP_STACK though.
>
> The main difference from my crash report is my test environment which
> was a downstream one.
>
> So it seems related to ST downstream kernel version based on a v6.6.48.
> Even though the backtrace was talking about unwinding and kasan.
>
> I will continue to investigate on my side in the next weeks but I don't
> want to block the patch integration process if I was.

I think we can assume that the patches we have queued in Russells
patch tracker at least don't make things worse, so let's merge those
and then see if there is more fallout we need to dig into as you test.

Thanks Clement!

Yours,
Linus Walleij

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ACRpkdbgZ2J_-9KLeRz2Y8G4%2BT2qPo5uax4-o%3DKZbVFRVEO4Hw%40mail.gmail.com.

Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBP5E46XQMGQEHODX4LY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id A3283880412
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 18:58:24 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-41401eb321fsf24075535e9.3
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 10:58:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710871104; cv=pass;
        d=google.com; s=arc-20160816;
        b=Hr4BUexOgFb/Tc9uhH1lQW4VXSPF2FkC+NbHKKcKDj8a0c6j6rpeKNbAse63qlumBq
         vtzE5b/D2CYWWYJzE8W1xOrm7AjArKZSmVsa8GP5Q7PVAmoEhV3BUrp8VjxabrVvFSYT
         9pOd5aRaxoCBTnEGkjChM+gPoz+CRdmE1jjsSZJbLQa7P+GW4VLqZoXpqOaVKn5+Wm5a
         2AR8C4zrhOmodmbPw42zh4Tvuxcm40f7Db/m/CNFOeINnM+yY4aAHZsme4CAjpC+V2b6
         ZqVVSh1qcpOlYXa9kAgl5s0TKTlRpCRANebxsssqMBMWAY/tXmYnMoVmggK/B9Rux3at
         UjRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=baGQ4F/HZfFhazsBRV0NgbmlMNVZAnDKVuleZlFabAo=;
        fh=6KKLwope9KcneAZ6muGlQGUM7YSyS9UyPMjozuveCzA=;
        b=0/wjBdA+jfReFB6Q9KCJdBsClnK8ShTGxwqffBGvFm9wFUrdung5uCb5m46h2eX/qh
         xImdekgb9qK0WvPpgbONxpED+rwPVbqs0uDb/ZmwvJnmVzQjJthuyQGoriexTDqN1pIe
         04KkwO7AKVr3u0iS8sCpzhretiDtKlOfqQuhw+vIvGph+XUBHMesPoCboGUvHAO+Gpva
         EmAInrREgn6VNoupS/B1AdkHAbJ2lgcpVn1TELfgHmIIp7C+7FcdL93v0taU487x1dsX
         n6Pcglf8I7Q5STVDPlVftjIwecPrP/j4t7WcPi9uYtL/3r5g4muLEzPbE/BP0r52ob9l
         suwA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=BFXwDtw7;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710871104; x=1711475904; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=baGQ4F/HZfFhazsBRV0NgbmlMNVZAnDKVuleZlFabAo=;
        b=Hm8dUdw5hNQSO8Tru4O8A7TzJnMOngoD7EFFRp1mOmZwqCZrPQwg3ivPtuAIlDl431
         Ng+9RULK6b3rFMPg7btLOL6pKYogF990opswViUPfYVbSh+Z+4rW6KR+CqpTQX0Ms8JB
         aikNXCPmyBEKNfjHf3Zn5AzagLt7MHMYUFq1ahwytMojeQEm4WodX8A6dlhrRqYZ0geQ
         fGcGQTPbqJOXLC+TxKxMTdtFfzx5g34tDZqSkps3Q2GbsfG3KLqEptDcgQa+s75aDVHH
         GQ9DBkkqIdAcxYHPYUisLdFTmf/KwxoWikr+Mz+2Wgm2fathlyzZcva8j45HKYnDYY9D
         K3XQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710871104; x=1711475904;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=baGQ4F/HZfFhazsBRV0NgbmlMNVZAnDKVuleZlFabAo=;
        b=QVm/bw5qR0Mhlp3Gri0O0qUBwAUVYNYd4WBYJcEJCaPbqwiEij4DSt3Qb4lWcOgZnH
         +B0dnnkAaPjsLxFsKQ1MZFyNSauVjLfXjC4ngx+827CH4tQLrqFw8ixfClNHjzR1Mo9e
         O0CgsVqzDowOI+MBdqzVDcTWwb5fBfA4GEJhNfhCbdoy8pfHo5S1dthnMIDlSTFpvv/I
         CzdYoer8cuuHx0XDRf0e6k4zOHeVyPZgodY4eyatrKAlaoh/XoyTt6WPunJQYl/mP4nh
         53eMB7/X+VHIHuLSBn+WNACXVL7AJJnVOk32vlwI0Vz4gvV3dIpfx5Pda90hrZnHxMc0
         /VFg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXeZLNCDmTCiyvmggPz5dC/9R2RseWHTZbQbfALKE99CpLmaIjg8Fvw3Ug57S1X1ZvocK/KDDRY1qn+YMfggwbH9W42OrDAqQ==
X-Gm-Message-State: AOJu0YwVTSMfB8emUhoRQ57fPFW7V992oCCiTuOjBREOqhOWcxODT5gv
	UpTds9j9BXbwetUcJn6ECXo/vZEv7DqUDKeAKf/hKa6lKd6p6ns+
X-Google-Smtp-Source: AGHT+IHJtkgJtFGtKH+9bK3TEb3gSP96IeHxOP3Fg1sBGDViRU9yloedV9Aqb9iLnqlt5kQsbwJpvQ==
X-Received: by 2002:a05:600c:524f:b0:414:2070:6385 with SMTP id fc15-20020a05600c524f00b0041420706385mr3925800wmb.2.1710871103429;
        Tue, 19 Mar 2024 10:58:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b2a:b0:414:66fb:9650 with SMTP id
 m42-20020a05600c3b2a00b0041466fb9650ls384956wms.1.-pod-prod-04-eu; Tue, 19
 Mar 2024 10:58:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXpk2q1lmC22ued5PffHXV9iUeiYfsq8YUN5CUK/x0pr1xPbmpXADYBsFBpb1fshDEcnoT89VYfg2PKhgXSONySQa120I1GsguE1w==
X-Received: by 2002:a05:600c:46d0:b0:413:feb4:d76c with SMTP id q16-20020a05600c46d000b00413feb4d76cmr11363669wmo.20.1710871101041;
        Tue, 19 Mar 2024 10:58:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710871101; cv=none;
        d=google.com; s=arc-20160816;
        b=mkcnRxoRIROi0Ho6EmCpX3iRwiHtpLiUiV71siofFfHuytkp8pRy5KHgHactWs91AJ
         8Id4un9FoTv7bE0ZzgpdBrrRQnhgtBxvw1UjoM/NhP0qvf29Q0EKeJUC+SeMY7xLenEu
         2piGO+PnRCi3gQFS5Dpq0ZOmDcgavvmGJ4iuiOtL3/YdqZKRspHuP1l/8JKanfZZY7uw
         R5n41Kyol4ysIPh5Zp0VfnnQt4+OPWa412ppNkSq0HQI02SSgfS297tsMa3BKzzMGIGL
         C34mgBPl9OGdougFT8x1SxFCNHwDwKf/rtKbEKaZ0VTCOHZCphxzhnpueHD35vJ792c/
         ViJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=twG2O+T6o6F/FN8MJ3T2+Oi98EiyVLX3AwSybqhHmqM=;
        fh=BlEMaU1xtmRv1DjfuPdN+coaWWz71dJXmKySi+Se0tE=;
        b=pnU2HWughShtYxDAJH4sgPngPEZ+iIMzlyqqTp3hhR5m+ETosEMAb5uzqtxp4TS6K1
         mVD59PIbLpl0LVK2uTUGyL4yAfhs4XDM/8pg9S4xckfJ+dOLPaT8Y18yPy8Hrog+Y89B
         ctV+1Hk8Mck+O4lYR8OHIDjOCFWGc3kBUhFTas+vw9f2n2wepdCvz6L9CE/BO7Oj+1B8
         m/bs9EuiTXMtpUl5eyB5PttBSZ4qSDt+OxYA1xKxJsaEBpl0sjbdjAWCBa5DwiAqhzkt
         YtxBkrvVqHj3NrK2ttqGthvcic7yX3VTGFDr7XVc3nvHn/Sd9dLr+A/hSYPjejsekFva
         B4zA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=BFXwDtw7;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
Received: from mail-lf1-x132.google.com (mail-lf1-x132.google.com. [2a00:1450:4864:20::132])
        by gmr-mx.google.com with ESMTPS id m3-20020adfe943000000b0033e082abbc4si603573wrn.1.2024.03.19.10.58.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Mar 2024 10:58:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::132 as permitted sender) client-ip=2a00:1450:4864:20::132;
Received: by mail-lf1-x132.google.com with SMTP id 2adb3069b0e04-513cf9bacf1so7431368e87.0
        for <kasan-dev@googlegroups.com>; Tue, 19 Mar 2024 10:58:20 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU6zGBXBRlDkAAanKTd8tdz9hvBLiNutuHMwSQV2KND+diRKyPhz1UDWC3bnL7R3un6J8Xk6WwFoxM/8Y/pDPKOrPnOVKCdTMPIgA==
X-Received: by 2002:a19:4359:0:b0:513:af26:8cd0 with SMTP id m25-20020a194359000000b00513af268cd0mr9515067lfj.68.1710871100283;
        Tue, 19 Mar 2024 10:58:20 -0700 (PDT)
Received: from mail-ej1-f51.google.com (mail-ej1-f51.google.com. [209.85.218.51])
        by smtp.gmail.com with ESMTPSA id o1-20020a1709064f8100b00a4671c92907sm6235147eju.28.2024.03.19.10.58.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Mar 2024 10:58:19 -0700 (PDT)
Received: by mail-ej1-f51.google.com with SMTP id a640c23a62f3a-a46db55e64fso140375166b.1
        for <kasan-dev@googlegroups.com>; Tue, 19 Mar 2024 10:58:19 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWntaFrkz1/aNBtQ+MOruLb4CXSUJpiWZJgZ0ey34Wx48wbCjnc3FpYt6r8q5vg2Ig5w0Cc0apiTh05ukzska25JomdiokQUo+vlA==
X-Received: by 2002:a17:907:7e9f:b0:a45:ad00:eade with SMTP id
 qb31-20020a1709077e9f00b00a45ad00eademr12086295ejc.57.1710871099106; Tue, 19
 Mar 2024 10:58:19 -0700 (PDT)
MIME-Version: 1.0
References: <20240319163656.2100766-1-glider@google.com> <20240319163656.2100766-3-glider@google.com>
In-Reply-To: <20240319163656.2100766-3-glider@google.com>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Tue, 19 Mar 2024 10:58:03 -0700
X-Gmail-Original-Message-ID: <CAHk-=wiUf3Eqqz3PttTCBLyDKqwW2sdpeqjL+PuKtip15vDauA@mail.gmail.com>
Message-ID: <CAHk-=wiUf3Eqqz3PttTCBLyDKqwW2sdpeqjL+PuKtip15vDauA@mail.gmail.com>
Subject: Re: [PATCH v1 3/3] x86: call instrumentation hooks from copy_mc.c
To: Alexander Potapenko <glider@google.com>
Cc: akpm@linux-foundation.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, tglx@linutronix.de, 
	x86@kernel.org, Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=BFXwDtw7;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
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

On Tue, 19 Mar 2024 at 09:37, Alexander Potapenko <glider@google.com> wrote:
>
>         if (copy_mc_fragile_enabled) {
>                 __uaccess_begin();
> +               instrument_copy_to_user(dst, src, len);
>                 ret = copy_mc_fragile((__force void *)dst, src, len);
>                 __uaccess_end();

I'd actually prefer that instrument_copy_to_user() to be *outside* the
__uaccess_begin.

In fact, I'm a bit surprised that objtool didn't complain about it in that form.

__uaccess_begin() causes the CPU to accept kernel accesses to user
mode, and I don't think instrument_copy_to_user() has any business
actually touching user mode memory.

In fact it might be better to rename the function and change the prototype to

   instrument_src(src, len);

because you really can't sanely instrument the destination of a user
copy, but "instrument_src()" might be useful in other situations than
just user copies.

Hmm?

               Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3DwiUf3Eqqz3PttTCBLyDKqwW2sdpeqjL%2BPuKtip15vDauA%40mail.gmail.com.

Return-Path: <kasan-dev+bncBDX4HWEMTEBRBVN54GAAMGQEOQJRWQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id CB70530B142
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Feb 2021 21:04:38 +0100 (CET)
Received: by mail-ot1-x33b.google.com with SMTP id l12sf7874081otq.8
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Feb 2021 12:04:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612209877; cv=pass;
        d=google.com; s=arc-20160816;
        b=ezq/BrpzS3D7/Tlrd12YyKpa5Rk+PHtA+6BUOAedEAAS0QDX+7cVCmJgTPKtFuVb5W
         B0xGpY2s4EyK9ClPhqGkDwy3MIxXyBBp5yNniAVZMD/eHXoNph9KF9wQEwnYBejkhkPs
         DGcVHFEGUkIC9ILzaKbLbjQM4UeMyAP18hyTQz1awKj298m7mq7hvG/MTuZcA7zPm5JT
         X1IyklJ0hhpW16kPVrMLfq1Uhavcmjz8qqXK/83rjGfiDeei90O3CLQWRZ5LRsjFQVZv
         XUuBkMsmIxi44/UE+E3RuwQQRvAYKNaTzbcaeBGKcesoXoZkseV/o0i3wxF6iYXimq7A
         qrlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=jA6yaABFqG8DA6DOgpuTdKl1kBN4XhcALBxMcfLsYZM=;
        b=jZsPMyMsbAPLuFNvitZNAcFjDSY9S+EEggr0+KfTB2aaZitS/OoSkIZi9Vw+Dr5svX
         3YWXAQkL7Jdt2d6EvJdmD1O2icxSE6rbn+GKtRx2Kd36DdJvTRdT0Wxv2aNo9ll7ZoV/
         2h5uYorStIkvswDsBWY3+e4OY2WXvBCiDpEYKWpilTs2jr07P/hhesR9UtROD+ZSshiK
         BJ3WV8xU0SzdHUTzzYs5VnEe/WkxiYTNJD61v3DJhAZc1mWptzAshPIgTNYHwT8TzlPJ
         8T9vv+z239deYO4JIY44Xpq7MLSC1LjYJqD/gNp6GCRYTIsK+0sStAfzgi6myNQIU/DD
         vJAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DQXWHKUA;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jA6yaABFqG8DA6DOgpuTdKl1kBN4XhcALBxMcfLsYZM=;
        b=cCLFlEs1iiduB05bV5QqCSK1kbohCSAZBSYqdCYLIafTqmDKIHBNqML+BGBn6hfGYd
         2b1rCy6owPR7nkByvvcq/DCMKD9EftWgozRuTKzX4bu9acYW2Por2UyEmuMYtr3F+q3z
         xTjaPl3AMgsPuZNm/MMMNeUH6MhwvrGHBcIEjgiUcZzMUqs4uvvLAEL7cSfFkkHvD5bH
         lC0+hXkqzNNm7TINFBj6hp9vAnLKIOiFrH1nKlJEn8libVg1aj+w8OIi3fMOQJIY1g23
         cYJBL6oLEogPAnwkoxgiQLi+1lf9nHifuK88wFmU5BGCkFoYFX7DVEQz8HHjaEwTnHNE
         AXzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jA6yaABFqG8DA6DOgpuTdKl1kBN4XhcALBxMcfLsYZM=;
        b=ddPPJASrVMbdIGwT6ajeNMWU7dvwdVBsq+Uc0zXGOP3DGZjlUME/atIuisDu+aZfA+
         EWkqvcbu3cfKtLMw3+SZ27arRsXo0JB64JI7BX/RyL5i/Y5LywfrDFAPw0GqAkNURj5F
         hmjaupuaR4DpQ8IPe5UBmy2HijT94laNnINl8LsFTDBz9LsWhnXglWzsq9OiG5/tWwg8
         h+/OVGmIevyBhh0tINFyAIWRzSvBzT66RWXvE+r+rOV8I2GUAEcQwSqyCpwknQxNU6Mh
         a26qEGs7qI8iN3WgmyZ4DHskV4S1faTeEhmUKDmKFTAdm1wZds4nG1V/EW0PF5LbNRlw
         Z4dQ==
X-Gm-Message-State: AOAM533WEVmdBMOB6inbFD9gunbmyD/PdENl7nQFVDuC5jH7dyTrjwb8
	o1OFk6s4JJ53EDTt7vFRm8M=
X-Google-Smtp-Source: ABdhPJxgDQthAsVk04Yr8Qf50mT8koWolwV7tfE+DukXzD+QacdPbzCVkSZfE2m2v2xmHLy4KksItQ==
X-Received: by 2002:a9d:4812:: with SMTP id c18mr12210064otf.160.1612209877819;
        Mon, 01 Feb 2021 12:04:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:cc51:: with SMTP id c78ls4314697oig.5.gmail; Mon, 01 Feb
 2021 12:04:37 -0800 (PST)
X-Received: by 2002:aca:f4c6:: with SMTP id s189mr364648oih.169.1612209877420;
        Mon, 01 Feb 2021 12:04:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612209877; cv=none;
        d=google.com; s=arc-20160816;
        b=ACCVQYS2w3Z9bw6nUHMU5dIVQ1W5qf9NJS1pdJ/adOTHPlzmU5eNgob4MoIWYs/zG9
         OjipDWOVqog0imy246i3f7+2zQEPcL2ujfkdCovmtkq3UFR6H6TcJkMZ/Bq1BhiWJCFL
         1M8uhhrRynuHgw1RlOOABFzQklAwmxVcYdPtsTQRQ5XQ4YVJJK1B3Pyuiwlm1BPyriSO
         b7QwMqRAJL9VQxCt8XFPoc51MrI+4COJBbqOjW8DpbP4puYqmbk2fp2Vu3iVHgKSH0I9
         Ur+xrozUI5RrvJTkqwhddLntOkZrksq8zBR/0SCu/Hxxc8empM8ZTR+ArF3O+tr5ZgXG
         nC8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Er+3gSvGmPD8gB+0H5nskQtEmoQnaFUKfPK4BzJ3IdY=;
        b=nEXAFbjgpMO8vSXKuKpRWQ9W6oubRObths81fH5Fv/jKzdC7DcT1KWmy4mNAdnsoFH
         QmeVaM/91wmUZCFVlSWvTB52sv3nWOm6WNNOz1WPnn+3T3jZEGB5f2OcR1Z3T2jCTi6D
         JN34cxMC07IXIadPSIES6OXqFnlxamZofYjXWuEy92wdKZUz/Rg5hcV3iqZwYAvnW5rc
         +oWwkipKTY17MtORvu8iuLBcv2UcOxpMXbHqOtkSOwaRBiYzglubCbBBjP4zxlmR43W7
         HFB/wm6O5/F9bJZSz5vtqNOssYMcOPI3ooLy2R4MPxuby1Hs5y4votHsiDw5u9XDPyZU
         7O+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DQXWHKUA;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1032.google.com (mail-pj1-x1032.google.com. [2607:f8b0:4864:20::1032])
        by gmr-mx.google.com with ESMTPS id r13si871657otd.3.2021.02.01.12.04.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 Feb 2021 12:04:37 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1032 as permitted sender) client-ip=2607:f8b0:4864:20::1032;
Received: by mail-pj1-x1032.google.com with SMTP id l18so285725pji.3
        for <kasan-dev@googlegroups.com>; Mon, 01 Feb 2021 12:04:37 -0800 (PST)
X-Received: by 2002:a17:90b:30d4:: with SMTP id hi20mr521695pjb.41.1612209876585;
 Mon, 01 Feb 2021 12:04:36 -0800 (PST)
MIME-Version: 1.0
References: <20210130165225.54047-1-vincenzo.frascino@arm.com> <20210130165225.54047-3-vincenzo.frascino@arm.com>
In-Reply-To: <20210130165225.54047-3-vincenzo.frascino@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 1 Feb 2021 21:04:25 +0100
Message-ID: <CAAeHK+y=t4c5FfVx3r3Rvwg3GTYN_q1xme=mwk51hgQfJX9MZw@mail.gmail.com>
Subject: Re: [PATCH v11 2/5] kasan: Add KASAN mode kernel parameter
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=DQXWHKUA;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1032
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Sat, Jan 30, 2021 at 5:52 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> @@ -45,6 +52,9 @@ static enum kasan_arg_fault kasan_arg_fault __ro_after_init;
>  DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
>  EXPORT_SYMBOL(kasan_flag_enabled);
>
> +/* Whether the asynchronous mode is enabled. */
> +bool kasan_flag_async __ro_after_init;

Just noticed that we need EXPORT_SYMBOL(kasan_flag_async) here.

There are also a few arm64 mte functions that need to be exported, but
I've addressed that myself here:

https://lore.kernel.org/linux-arm-kernel/cover.1612208222.git.andreyknvl@google.com/T/#m4746d3c410c3f6baddb726fc9ea9dd1496a4a788

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2By%3Dt4c5FfVx3r3Rvwg3GTYN_q1xme%3Dmwk51hgQfJX9MZw%40mail.gmail.com.

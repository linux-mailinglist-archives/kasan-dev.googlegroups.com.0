Return-Path: <kasan-dev+bncBDW2JDUY5AORBSM5SC2AMGQE3ABG4TY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E0079240DE
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jul 2024 16:29:30 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id ffacd0b85a97d-3678ff75122sf25581f8f.0
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jul 2024 07:29:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719930570; cv=pass;
        d=google.com; s=arc-20160816;
        b=TCxbD+do25X7wqUcyzmCREjfYZf4tf31xi04xOcx574h5sCtomU8Y2bkQHjtzet58W
         UeL7setba99d5qx3ZnZGv0VV9phR8ASx+cWMAEC82TNPgwx5B/mfZyXHMl1m3ga2+Jkm
         y1tOjqPoXDy8/nihXS4VY1XABW6o3/sz5mOOkV07Qk6ipgmRPlsiIwaBfp2Q54GQpB0O
         7f3AqjweKpbcpBRYxyCNzxOT4zATCsKt9qPXhPVpXrUOPPv2tkgGfkjPTF+xxFMeJ6Mt
         oHTB4lYpkrW+cYwoFKE/TuPabE+fyNQ4Wa7Ts+N6M74MEMIKS4CvuQNHlYnaWkia9BIh
         Dvtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=is/rJgE9/gOIYFh/SiwFVqKjA9w1OwvJmivnuRQPHyA=;
        fh=+m6IgxNF2EimNt+WQZZDgm27HNbymDv/nkSp1TEzix8=;
        b=OjM38gQ3E/SXg+9LjC5GYbYaUOgNqEKKRwzP53p2kHVNLHH1Y89oo0eW1xPrMFjtI6
         fbPbrpJgSsOlTv0Qx1gpBbV1MCMQRCRzcMnuqviaTOKdjTgYz3PaRUffMCFDh2L0zf0d
         et9cRwomliJc7pduDHpAg0PjKioUPLv0iY5yQafFud6JFOkQaSSY3xo2ISpfqWjvDPQ3
         g3liBwsGJmTsgNQj4a5e2jSEqTf+h+6B1i/o1J+d/J44mjO2W+KGDE5cYWFvXCMQCIS5
         FG2q1bytWUbCrbt5MuVSi7uLGFELC0JwulsdlMz/J18vdeVcPJ6mRml+PO9q5puttqpa
         L6tA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=MhrlQl7n;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719930570; x=1720535370; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=is/rJgE9/gOIYFh/SiwFVqKjA9w1OwvJmivnuRQPHyA=;
        b=R1LsgSCzKlRE1Nxw5QB6DSZQhu7Jn5XDGti5bfYuV/JaGZlTJMQVYhcqLxyiWEYtq8
         QT/O0+DswbgusbhD8h4ZN827sP3iWqc0Be5LcrZBgwbo4hoW9YlFMw7yEQ1Ki7sT5lht
         xF5S6MZHwtGe78tMHAHVWcjK4841kdIanLihy7ezFghxwctaWicikRGCzNIgJFMTKNOR
         Q3afitFMn7gjbq16dOObXFZPKLMVbUZaaDHybufz2jSCU60SHs/AGKwRGIhkEammi5mu
         eMQ+4DwAwGvWlQeqXrR+JONn/vG2spqr9kCVLz5zKveRZJecltpJ0u5pt5+Al7HWOAm+
         anFg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1719930570; x=1720535370; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=is/rJgE9/gOIYFh/SiwFVqKjA9w1OwvJmivnuRQPHyA=;
        b=K6A4mZPSqC7jY54mX8DmSMs46rmf7pWwBSE3nOoxxhJ+o5wvmC4+Q9vGYZhak3PZu7
         VLbgKa/5V62LCm69uvlkUD1BJqXAu9Ge2JG7lUouEs9gbS+NEWSMzN1mBx6dxADBHgXr
         ud1Q/tD3NURZQ2pduGbyYfXXxcwllHa2xLW4eXzXGrFs5VuiQ/r7qQeH/x/XXB0/7mwF
         9369TYD/gucpVXBnmiKiAN7x61iZEwXeeJ52f94NbPzFGGa0cVvdP/qmJgw4OWgJ95Ne
         01HEbxYiaeKWJxdogRTJGYIAfcNQ8Hew4YTbiee8HarT1L6L1MLpSJV0DS8RPbf+Jweu
         Sw/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719930570; x=1720535370;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=is/rJgE9/gOIYFh/SiwFVqKjA9w1OwvJmivnuRQPHyA=;
        b=urp7pUJ1TVFkf8y1UzrtQbQ2GObw5p2d1WncnrcVvjerUXMtjRrXamCvtaige2TTrv
         mrZjqXjpb2pEMiv5nc4RHGnnpM0EnuLt0sNsNvXodiie/K8vAwXvAD4yJjXosf6hJ3J6
         FLg2rpaPSaoNq1VfI8U4kyTOG0sdhtENLEt0cp618ePMwFFtHIRVbbTJR2bVSSzUsX63
         /EmI6Wh9xOJ5BL7mtccSxI3jnyHEiCym17EMF43qsN1uJre5UPPyIx11CmAD7/v6R0RV
         e9uC1Ny6IYk4UJDDso4G8F4bKEOvZkrwYOrvbYe981vOcpH+zExqWOD1+Qu8ZdDNNEoT
         xKqg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVr+GUl4jfbNPhYsuwpH7dLteHYHict5/r5QQB3LOpdXlCsUsUvAZ8hUX1wfJb4vKbMrhqmsbiW9OhLkZkexD9p+JVYpQ3fwA==
X-Gm-Message-State: AOJu0YxT4Jn6xRsXSxR7naR05m7jzyXKBN6KRtZrBIs7ezMv9PpbMgoS
	nba8xn8dSrs78q+8tE33Ko30O6OtFu1rrpXRnX9DgkrO6qVpWFmt
X-Google-Smtp-Source: AGHT+IGHNf0ZLfAOyHioS4e0oeGr55OHNrERUXSaN5jlzdRqXWRBJKLMCuuf5GxobfyqstXTsFGllg==
X-Received: by 2002:a05:6000:1566:b0:362:3b56:dbda with SMTP id ffacd0b85a97d-367756997a4mr5911107f8f.9.1719930569369;
        Tue, 02 Jul 2024 07:29:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:c4a:b0:362:606d:1022 with SMTP id
 ffacd0b85a97d-3675ac47452ls1547874f8f.1.-pod-prod-04-eu; Tue, 02 Jul 2024
 07:29:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVEt9FCmLlA9y6kGFsTntmMl8b1CWiEcHnp6RPwJ2EbXDw86fmpNy5TtG0utcxtXRLxr7owUxxzfprJbg1mnZbYn4xvqZpXc4Eysw==
X-Received: by 2002:a05:6000:156c:b0:366:ecd1:2f38 with SMTP id ffacd0b85a97d-367756996c2mr7960307f8f.7.1719930567476;
        Tue, 02 Jul 2024 07:29:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719930567; cv=none;
        d=google.com; s=arc-20160816;
        b=akkvaBjsQurwIs1GbSDTx0WgeHfiSkYFdQhMGBQKDri4m8bb8cFGhc2Fx1Ax3atAC4
         bU/22pdhpSe1ADEtjjwCfoc/6RuyXqeST/sAehe1G/Ijf3f1k58/Wk+pFQ9LMpCUicOn
         wUo58Qsd7xd7Azmlj7CcYegHBz6PIWNpuXskl6omOA/OSYhJtp01G6kNfH/v+ycrAwnN
         0mIo/pvmr2aPbhRXz/ysIvI+2yy/OqnPjdzI3RgvXcwjURTXgcFjyp0Gdr9CMfBSiul8
         hOd2P69G13LL1iWtoEW857e4scRJTqGWlFZ+LCUbDRKChm4sgxpWSe7OHoVqMNmZ4MET
         bFWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=1IAex0C8drdlkZxMli/n3mCvgYAdPAKLrdakmDvXPaI=;
        fh=MCTK3U+LupGYlfUp5uEbRMVzKTfTvH7sx7wXtPy2nLw=;
        b=eASXv5uNP8yVagprdnnFXNIRe3EUoK1uaxRThVZRFirtUHTYkeWMDg+/moVsz8Bzrx
         DTzPqfRByPGo6KcD1bf7BcKzOUFN0HA7xUWI9OCtnQpwfshJRHL0/UJdynvZeLWWx5xs
         HTGTF+8hUnpWw6YEtMDob+c2FePdGeJ2R9LVkFPiZCPHJQjk+lhdxL2aq/Si9jXR2vx9
         T+r79q+2bmgqQXjl2c1evvv33tsUTppiJrTmmJOHiE5zA+XwAlEh1JcG/pPlY8o7PuJO
         m36bfSu1yieL5Gy6czObYaJ1YoKrSXDU5HMo+UvaZr7U39rNKgPCMGoeJ8VCDEsVynbV
         F7xQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=MhrlQl7n;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wm1-x330.google.com (mail-wm1-x330.google.com. [2a00:1450:4864:20::330])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-367865c23d8si57688f8f.0.2024.07.02.07.29.27
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Jul 2024 07:29:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::330 as permitted sender) client-ip=2a00:1450:4864:20::330;
Received: by mail-wm1-x330.google.com with SMTP id 5b1f17b1804b1-42579b60af1so23009825e9.2;
        Tue, 02 Jul 2024 07:29:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX/2ujc1C3Hp/g+tTEPfK9ETTWALQ03R1k+9kqjd/HOTBcc+aWQoBqxZCdsZE4BDpWwYibUNyBduWFQfl8YdE6bbPi9YV0DzZRKw4Babx8EB2B9QeqaqE75J+/RZEEY9naBG23NK9ixTjuBBw==
X-Received: by 2002:adf:e2cf:0:b0:362:dbc2:9486 with SMTP id
 ffacd0b85a97d-36775728c18mr5152575f8f.68.1719930566909; Tue, 02 Jul 2024
 07:29:26 -0700 (PDT)
MIME-Version: 1.0
References: <000000000000a8c856061ae85e20@google.com> <82cf2f25-fd3b-40a2-8d2b-a6385a585601@I-love.SAKURA.ne.jp>
 <daad75ac-9fd5-439a-b04b-235152bea222@I-love.SAKURA.ne.jp>
 <CA+fCnZdg=o3bA-kBM4UKEftiGfBffWXbqSapje8w25aKUk_4Nw@mail.gmail.com> <ec7411af-01ac-4ebd-99ad-98019ff355bf@I-love.SAKURA.ne.jp>
In-Reply-To: <ec7411af-01ac-4ebd-99ad-98019ff355bf@I-love.SAKURA.ne.jp>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 2 Jul 2024 16:29:15 +0200
Message-ID: <CA+fCnZfxCWZYX-7vJzMcwN4vKguuskk5rGYA2Ntotw=owOZ6Sg@mail.gmail.com>
Subject: Re: [syzbot] [kernel?] KASAN: stack-out-of-bounds Read in __show_regs (2)
To: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Cc: syzbot <syzbot+e9be5674af5e3a0b9ecc@syzkaller.appspotmail.com>, 
	linux-kernel@vger.kernel.org, syzkaller-bugs@googlegroups.com, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-mm <linux-mm@kvack.org>, bp@alien8.de, 
	dave.hansen@linux.intel.com, hpa@zytor.com, mingo@redhat.com, 
	tglx@linutronix.de, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=MhrlQl7n;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::330
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Tue, Jul 2, 2024 at 8:11=E2=80=AFAM Tetsuo Handa
<penguin-kernel@i-love.sakura.ne.jp> wrote:
>
> Well, KASAN says "out-of-bounds". But the reported address
>
>   BUG: KASAN: stack-out-of-bounds in __show_regs+0x172/0x610
>   Read of size 8 at addr ffffc90003c4f798 by task kworker/u8:5/234
>
> is within the kernel stack memory mapping
>
>   The buggy address belongs to the virtual mapping at
>    [ffffc90003c48000, ffffc90003c51000) created by:
>    copy_process+0x5d1/0x3d7
>
> . Why is this "out-of-bounds" ? What boundary did KASAN compare with?
> Is this just a race of KASAN detecting a problem and KASAN reporting
> that problem? (But as I explained above, it is unlikely that the thread
> to be reported can die while processing report_rtnl_holders()...)

KASAN creates the bug title based on the memory state byte, it doesn't
compare any boundaries. So if the memory state got
corrupted/out-of-sync, the title can end up arbitrary. In this case,
the bad access likely touched a redzone between stack variables, so
KASAN reported out-of-bounds.

Since syzbot managed to find a reproducer for this bug, you can ask it
to run the reproducer with additional testing patches to check various
hypotheses [1]. Perhaps, you can write a magic value into task_struct
(or into pt_regs of the task?) in get_rtnl_holder() before saving the
task_struct reference, and then check that marker value in
report_rtnl_holders() before doing sched_show_task(). Depending of
whether the check succeeds, this will give additional information.

One other thing that comes to mind with regards to your patch: if the
task is still executing, the location of things on its stack might
change due to CONFIG_RANDOMIZE_KSTACK_OFFSET while you're printing the
task info. However, if the task is sleeping on a lock, this shouldn't
happen... But maybe a task can wake up during sched_show_task() and
start handling a new syscall? Just some guesses.

[1] https://github.com/google/syzkaller/blob/master/docs/syzbot.md#testing-=
patches

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfxCWZYX-7vJzMcwN4vKguuskk5rGYA2Ntotw%3DowOZ6Sg%40mail.gm=
ail.com.

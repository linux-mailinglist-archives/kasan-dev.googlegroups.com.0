Return-Path: <kasan-dev+bncBD3JNNMDTMEBBLHYS3FAMGQEJ3LDQ5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id CB481CD1DE9
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 21:57:18 +0100 (CET)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-34c704d5d15sf4245493a91.1
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 12:57:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766177837; cv=pass;
        d=google.com; s=arc-20240605;
        b=ctJmEilQamBxHww4qu72/cH4Jgd9R/oRPmuQBF7cWF8EPb1YkdDNE8TCqWmZtBk9T3
         CWrQtLvPeS0nSguz4XRosfiJqX8UHFjT+TszQA+Jq/71/86kN4vzNGAk8eUzkrwQm1br
         MuKCVCWNxmIO5U7G1NNQq0tVSe4FYwIES/LADPOZHryrUS3dhtRg/0LaMhS2yO0sP47m
         rZ7sXN1nQZG2NEh/E4S11n2NSOQ3K1G7vId68rD2qn/GNiwmkGaS/O0u41/reenkcoOO
         tqgBu3g9E45n6NqM3/m5xdCMJPIEjHRJozjMWyTFSwLQRWDiiP3K8P3Gu8QcUzMcTNWP
         KonQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=HM6k9uGHTyqHs3sNd64rPz4+mX2NF62T37sbAlN4M6s=;
        fh=ck0jZTfw9591vWEdO4cRLuZ/+f4jHcnGsrX1fT1jZdc=;
        b=TJ5CV/ZjI6a11Ly8s1SstUiDKTvGZ9tjIzQoDHRwv3LNnCzfOIn4Xk0MC34BJDItox
         EUXlGRq2zanRhwUeum5iEbwWrvB11tnxeZ2xyt2cZV42kFfZzC5S4fUV6/CsyfeFf/Gi
         tYrE03Q0Pi/FrtF1073mA1w4llj7y/s0aIjf6xlVH+BtTmGw/4fr1qwKcYtBWUKBSW2g
         2R2RQt8vOZugxuytIbkASBdDCfWqE9GuKVDrAyPO9xaBbOqu8AVNlF/EhQ3ffwpo14wd
         Jnine5Of+1u9bbCUsH/HPH7QPMQPZcLgTl6DJ6G4aPEVsLH49ziHIAa0esMN1dQGtnir
         cyyQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=42advhE8;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766177837; x=1766782637; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=HM6k9uGHTyqHs3sNd64rPz4+mX2NF62T37sbAlN4M6s=;
        b=tacUa+Hd+CC1O+bCfkap5eYNyZPiVBfJJvoP7U51Vio5LkPfUHL3JtgR8nBFVyup12
         uEz27VvLZZ9+H8rzn2GsUkshBraycAvh6itrfEybEu9yRx10iVnPQlZdk4iVKM9nqkhE
         VZ4wWOZlGHTvko9WY/rKT2RlA+dsAOrDmNQEn2dAluluRTlv+oShFS3HCJ2zdCZfgpCp
         9dLq2p/ic5/a9jYQGoo3Pc4ZEMDs4av19kmBD/Sq1uekcwpp0dehi8bg2RomFTGlYzew
         jCDsUgiavSYjPz2FTJuAx2auPrbOzpEBfIPrkGWBOVY+aGBOcKYKpyaLPsEfVt9SH16/
         nFJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766177837; x=1766782637;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HM6k9uGHTyqHs3sNd64rPz4+mX2NF62T37sbAlN4M6s=;
        b=D/rXaeoAl3RkBtIugPzG7RX5q9fl0RnU3wzQIPO45gwlBTJGSx/EHxRhgKYyO73u7N
         OVpiMBLDWN8mXgRxSwccWAwBCAi/wbLJnKMMTo9qdK+BOB+dt1cErg3TAnXUBWdkFdR3
         f8o0HbMVvP4bDkQFqX0cR38JW/2AB6OYrhxOIggP+jOgW0bFM9AeCm39C7iFgcuZ1EUw
         ge1KAyWOSGz9x7a3e1RTAPzGxGROXz24Tk1J0KOY7CxtMYlVtZJahHeftn3Dcf9TbN/+
         Ci612LcLdDdSGiP3MWaVzfYkJKF0dDod05Yt76lWB5gNAB47W6fLMH07CS50b3s1USt7
         d9Qw==
X-Forwarded-Encrypted: i=2; AJvYcCWQ5i/AGr2c7dV6oZ+Y7L6YpCO7pbeN3AJy3agZeUmXg9ISElBnOYKVBZVac7cMTVCE0BlsgQ==@lfdr.de
X-Gm-Message-State: AOJu0Yw+WJ614wqq9mBSyvtsAliLoYRXfOkywdHe+bx7Y8n7nzXokg1Y
	w77YEeZykqyyMHUA8XZQ2m9rq+S/OJnzvdgyjWqg0cSoedzCREERi/q4
X-Google-Smtp-Source: AGHT+IH2uvUZmXB1MfB28M1T788nvXuSP7ISaeeGkW6/nEgRBCPDKh3AJ+DFds2CBbjMfifN7Y9AXg==
X-Received: by 2002:a17:90a:c885:b0:341:8ae5:fde5 with SMTP id 98e67ed59e1d1-34e921bec27mr3384531a91.18.1766177836805;
        Fri, 19 Dec 2025 12:57:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZ3TpX0+2/EdJkDqElC70XV82C0JNKBu3AeNoiczuL6uw=="
Received: by 2002:a17:90a:db81:b0:34a:48fe:dff7 with SMTP id
 98e67ed59e1d1-34abccf6207ls8249030a91.2.-pod-prod-03-us; Fri, 19 Dec 2025
 12:57:15 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVLrd9E1bQBswGUHY+0bD1+6SGBcRjkz7OhAbv9SMWzRo0L2aFZhaY3baagirDwZ26GxmX6cXhkkRs=@googlegroups.com
X-Received: by 2002:a17:90b:564e:b0:343:7714:4c9e with SMTP id 98e67ed59e1d1-34e9212f28fmr2774027a91.2.1766177835331;
        Fri, 19 Dec 2025 12:57:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766177835; cv=none;
        d=google.com; s=arc-20240605;
        b=ZCCJCXWKStRXW1yVQ0S/JtJHF2KSa9oPV05+4uwyrSJCDJG3Iuab1LPqO3H/i3WVec
         Dm0aeLjm9f/VraR0EfXrTwK4sjUbaRy37gJy7Bb6CFm/gkprLibE0emuKYkbaPmxsMn+
         TPlKYa2rEByH0f1VHOdsQuA/jkiPP9REK4L9KDqxcwqboi2Nq0jCnD2iwM6RQj7vXupt
         9wh6lJG+o9uVJIz8VOqic5WNT3N6qaJy3gukFUHrseZ6DSpCM0weVSvCga0u6ADeSrB9
         edI7ygayCLkMWgJpC1Da1kOLdsJhSe0nxUvBxamCHOF2jL/WtzlFfB4Ex+z0AYmZJH6i
         6h8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=4FWBwq5pA2UdoaEgzi2KEETeO4vK6VBDGoxeKhWq2EE=;
        fh=oscsWGUi8qXSCGbxjzWMCAbvCbb+T4RkBriBWr6Vjhk=;
        b=jH3auIazYAmZItK2BnUYiWaGgGFRnuP41FgzO6+QU4Oi/WQWsfCLI8ZXqSJLrHjGpQ
         8PLeeYqq311y1JO9eUZ1cBY4fgiHRNjb5V8kY90N3YpWOuTdi+NL2pwpke4nWifiHaaP
         NFd7hfVU0bn62QTQQqfT/2p42kl54uIOy35iD8R7Vxns8M5nYXt3flb1BbJkkW6sZZc9
         w9mF/gmSefYbpNGgahFviNVTbRmZjJ7P/YuOGccyx0eivKRGAEC2ctOAdVdEMF47FfVg
         fWw/TucgfFyTBotalo+cJTPdCuwzdUxMaKMHxwyX5bH8DyTGfFxVBBrPW9fg072m3UXR
         JBKw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=42advhE8;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
Received: from 013.lax.mailroute.net (013.lax.mailroute.net. [199.89.1.16])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-34e76ee8e09si78908a91.1.2025.12.19.12.57.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 19 Dec 2025 12:57:15 -0800 (PST)
Received-SPF: pass (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted sender) client-ip=199.89.1.16;
Received: from localhost (localhost [127.0.0.1])
	by 013.lax.mailroute.net (Postfix) with ESMTP id 4dY0GL6DqzzlwqQK;
	Fri, 19 Dec 2025 20:57:14 +0000 (UTC)
X-Virus-Scanned: by MailRoute
Received: from 013.lax.mailroute.net ([127.0.0.1])
 by localhost (013.lax [127.0.0.1]) (mroute_mailscanner, port 10029) with LMTP
 id cbXucOoI7gI2; Fri, 19 Dec 2025 20:57:07 +0000 (UTC)
Received: from [100.119.48.131] (unknown [104.135.180.219])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: bvanassche@acm.org)
	by 013.lax.mailroute.net (Postfix) with ESMTPSA id 4dY0Fy2c2mzlwqPy;
	Fri, 19 Dec 2025 20:56:53 +0000 (UTC)
Message-ID: <4d6ba8aa-cc33-42a5-ae28-7a480d660c45@acm.org>
Date: Fri, 19 Dec 2025 12:56:53 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 18/36] locking/local_lock: Include missing headers
To: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>,
 Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
 Will Deacon <will@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>,
 Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
 Chris Li <sparse@chrisli.org>, "Paul E. McKenney" <paulmck@kernel.org>,
 Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>,
 Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>,
 Eric Dumazet <edumazet@google.com>, Frederic Weisbecker
 <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>,
 Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>,
 Johannes Berg <johannes.berg@intel.com>, Jonathan Corbet <corbet@lwn.net>,
 Josh Triplett <josh@joshtriplett.org>, Justin Stitt
 <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
 Kentaro Takeda <takedakn@nttdata.co.jp>,
 Lukas Bulwahn <lukas.bulwahn@gmail.com>, Mark Rutland
 <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>,
 Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
 Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
 Steven Rostedt <rostedt@goodmis.org>,
 Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>,
 Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
 Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>,
 kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org,
 linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org,
 linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org
References: <20251219154418.3592607-1-elver@google.com>
 <20251219154418.3592607-19-elver@google.com>
Content-Language: en-US
From: "'Bart Van Assche' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20251219154418.3592607-19-elver@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: bvanassche@acm.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@acm.org header.s=mr01 header.b=42advhE8;       spf=pass
 (google.com: domain of bvanassche@acm.org designates 199.89.1.16 as permitted
 sender) smtp.mailfrom=bvanassche@acm.org;       dmarc=pass (p=REJECT
 sp=QUARANTINE dis=NONE) header.from=acm.org
X-Original-From: Bart Van Assche <bvanassche@acm.org>
Reply-To: Bart Van Assche <bvanassche@acm.org>
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

On 12/19/25 7:40 AM, Marco Elver wrote:
> Including <linux/local_lock.h> into an empty TU will result in the
> compiler complaining:
>=20
> ./include/linux/local_lock.h: In function =E2=80=98class_local_lock_irqsa=
ve_constructor=E2=80=99:
> ./include/linux/local_lock_internal.h:95:17: error: implicit declaration =
of function =E2=80=98local_irq_save=E2=80=99; <...>
>     95 |                 local_irq_save(flags);                          =
\
>        |                 ^~~~~~~~~~~~~~
>=20
> As well as (some architectures only, such as 'sh'):
>=20
> ./include/linux/local_lock_internal.h: In function =E2=80=98local_lock_ac=
quire=E2=80=99:
> ./include/linux/local_lock_internal.h:33:20: error: =E2=80=98current=E2=
=80=99 undeclared (first use in this function)
>     33 |         l->owner =3D current;
>=20
> Include missing headers to allow including local_lock.h where the
> required headers are not otherwise included.
>=20
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>   include/linux/local_lock_internal.h | 2 ++
>   1 file changed, 2 insertions(+)
>=20
> diff --git a/include/linux/local_lock_internal.h b/include/linux/local_lo=
ck_internal.h
> index 8f82b4eb542f..1a1ea1232add 100644
> --- a/include/linux/local_lock_internal.h
> +++ b/include/linux/local_lock_internal.h
> @@ -4,7 +4,9 @@
>   #endif
>  =20
>   #include <linux/percpu-defs.h>
> +#include <linux/irqflags.h>
>   #include <linux/lockdep.h>
> +#include <asm/current.h>
>  =20
>   #ifndef CONFIG_PREEMPT_RT
>  =20

The abbreviation "TU" is uncommon. Hence, please expand that
abbreviation. Anyway:

Reviewed-by: Bart Van Assche <bvanassche@acm.org>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4=
d6ba8aa-cc33-42a5-ae28-7a480d660c45%40acm.org.

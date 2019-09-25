Return-Path: <kasan-dev+bncBDULZYNR2QMRBGVTVXWAKGQEK4TWFYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id E22ECBDDD1
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2019 14:12:10 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id z1sf2265609wrw.21
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2019 05:12:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569413530; cv=pass;
        d=google.com; s=arc-20160816;
        b=hkjzM6hkqfzYGw4aHO1LdTc7W8C6DYEQVXqb/HKFd1bkFPs7ohEDvV61F53BlfNVSZ
         1Oq7XhTC/UlCSohBVajrVTG4G8l3yHZWWLTCqN+m/o8mQmZvGfIzD8Dzk9oCPGDZy/bh
         7sDGZ5V8LuPbsOlDZJJtVEcGlCe18uQynNVHpYiyHug3qFx/OIYL6zFCuY5430MKybFR
         ppztvlFr5W5ClayIW25gskhPovfCdIegXbTXlHlavcg4izk1Mucm3RUwQTs86++NxTk8
         FS4rXzC6+G50hTTopJFDpprKnSgQjMjDZYuEWJpve0hsZ37I1dsSRqpRzH5Q0LiFC4EB
         BoLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=d8C62YKjfnz1vaUf50w96Q988B9Bx5BPZ4cAZfL07XM=;
        b=qaGxK4qIFJOhLdCdiXPycbTfh4nW8WlKUsmrCIwNO2L3PfZrW6MimtFvTR3Y20F2n4
         nOFMS3yDijQ3cUAfmf94xfzlDgW4kDUnDKLDyjDO96tS1Zb+Sh/O+draPO/Wsi4PGR3X
         RVCwjeMdqp725Ip/cRqnWFPGh3ztPzEXMWqqjHT9JL/PGdo3g4eWHdsTwdMYDuuRGEmm
         OAfHOL07VQeAvRC2trQE+yR3dy00id/sNsSkV17z7/krufyd3VPk0nFQ/VjECL8zzOyi
         2i/BKrhpp8xa/ytzhpVodYerexLWZdIEsKmkDgZ04ITaqlgVMj+O4Q3uhrbYc183m4d+
         zQtg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=e0naPQpn;
       spf=pass (google.com: domain of festevam@gmail.com designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=festevam@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=d8C62YKjfnz1vaUf50w96Q988B9Bx5BPZ4cAZfL07XM=;
        b=ZUffqCrGHPQ7Spt0b9hhkEZOfZdGrrIkikHBT9rB5GEgSadvYrxmtJUq8F62u5BI94
         70YVzPZcixx7j5QtppRm2HjQkNWpHzn+8BDlNoeTsEDG5gtm5kCHR6tQgn+vUCv+MJrr
         /7V0VsvEMgwlkvoDThwaxeiyhA8F2IB7iIYg6AVfxJXxc17egqIlkLJq/s2BjwiDeVBq
         0+o95tT0dQTjqHA/eMWL5sjTLYVTUCAEsX05F0Bvb9nkJdwM0Pj7QV+dLopcpV4rwo0B
         XntVjAyQSdhBzEDv4bNhb14cCTfFxvahZFEI3YPr2e/rdAhYqO6NvHU/uNzoRI+FTT3u
         atbw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=d8C62YKjfnz1vaUf50w96Q988B9Bx5BPZ4cAZfL07XM=;
        b=Ip0FadcUoFCMCHtxjNRacvVA8Fp69/0ZVsM+Za3GyPwFmafXQtelOhSimX/kd5tqKz
         OU0Medz1joo5y6nZ9lHHfDDg0P+Yk3pbaael0gYRJzNfAY+p3sqSHNQrsLW2xb3bJQ7x
         fhwmdsMBGPnd+ch1/VWoiHNoSfqN3N+3ufVRBk5Q6oUvC9zzaPzZig5n6JXTU9WgjNbY
         jha0onZ7CR+mGd+txkP1yFgeu8NTR/ME0ISO53kERgWxG0GwErYjyS+4+vtw3vWtlleL
         /36uO5i5eD2KvmqtvYphf6roW6cDyZX5qA/Nh9nADtGNlVD49cYpdGPJLX1NOKoYUfAd
         fPcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=d8C62YKjfnz1vaUf50w96Q988B9Bx5BPZ4cAZfL07XM=;
        b=dxOnRvqDmB3q2bWswlYlGDI3tpHkp9qQiQPX6UXASZa8i7k+5mMoR5rJnLtbRUriET
         CcswZ84Gb7Ib/MWH7ZnT2ddRc7NuPocXhEijeL+bgcg/W9dxMb+jN9RF2/03t3RgOYSp
         MTK45ycxJLoLt+EaiQfWRNRfwXk8hVTyvnhhvD4yUtMiJL42RM0FuavQ3+/rXk/ZmK8m
         X+vRxfHcobLPNK0d1z+njsEfJMSFbGnH0/3c74S0rL9xDLD7bls3jjk1/V42RD/fSmh9
         YenKpFyrFvmCVKb49UWsoVolmAZx6kthHnNo7rA76FatzvK53TvoeCoprhnpcur3Jh2d
         Fakw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXRGafUAmTSzLlkayfUg4nuP78D7T0kXnLL+Zq/iRCltCLTkYTz
	UzqbZ7UEt/zL+abSRHd61b4=
X-Google-Smtp-Source: APXvYqyyo4O0gnQn5/jN/W1dhc+Wmeydv54YFilEH04ZTfBAlS6W0fT9bd+r0qQes2ujd363/krXew==
X-Received: by 2002:adf:d1a4:: with SMTP id w4mr8694687wrc.331.1569413530563;
        Wed, 25 Sep 2019 05:12:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:526c:: with SMTP id l12ls2136838wrc.12.gmail; Wed, 25
 Sep 2019 05:12:10 -0700 (PDT)
X-Received: by 2002:a5d:4fcf:: with SMTP id h15mr9550148wrw.237.1569413530152;
        Wed, 25 Sep 2019 05:12:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569413530; cv=none;
        d=google.com; s=arc-20160816;
        b=KgB5WSHRpZaU81X7kiiYlFkeuUgxzi1zlo9tXotfP2WUCICxr/TbobpWTv31gcH6M+
         eni7daQnHaJZgprepVDW97oUaVD79obNA4ENZZD4q8OmceBkgC3HZvxP/xDJcgRi7C5v
         +tto43fcBiulYrtjgjb1E0gVdR1wyr3V+m2TmhixgAIos4YcCaXcQLxDyXYTZyNX4A2g
         TJh8Lt3oDna3uzg3aXRQ9rO8I77KhQ9EJ38Uz98JsWsmadMSAGmO1S99xn4LER++j3a7
         wSlNT0S8598uGB2TqIWuvCmtlV8qAGJqD+G09mlq2B/iO2pQpPQJV0sP4HHpAIdI+uhv
         6avQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hUmVUwvSY/aeCErtOWtkiU7kxhgjU/DkZwXUVKfeXYI=;
        b=aDfQL1l1qkFb/l5egrvkOAiVLA7HDpNfqSEdLc/A78uqszzlmobVw+MXDt/K0oxyzz
         VyVatitsawji1cKBd+QkGJXkC/NcLk5ac1zAGqwqjvmEow43fqfcC7SJkMLXsHSEBZPL
         FT0tVvVTsfczBNzm3gIkBBpIhwByQI365NcXXQPBYdYamexNpJlqaULbNJL5Tu39S2gh
         xGlTmXP1bBsc+sTpGMUCVqpQv0+oxi5hSqXapZaWoMQXhTfgCpTCwhJXDRedx2/bdvPq
         27giFZ/bTjQ27zkPd6F4y00kIoGWy4ZqVSQ8LTeUO6PfohNIKA2cUhZq+/yzBhUj/hsM
         zfQA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=e0naPQpn;
       spf=pass (google.com: domain of festevam@gmail.com designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=festevam@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x243.google.com (mail-lj1-x243.google.com. [2a00:1450:4864:20::243])
        by gmr-mx.google.com with ESMTPS id x8si231827wmk.2.2019.09.25.05.12.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Sep 2019 05:12:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of festevam@gmail.com designates 2a00:1450:4864:20::243 as permitted sender) client-ip=2a00:1450:4864:20::243;
Received: by mail-lj1-x243.google.com with SMTP id y3so5369389ljj.6
        for <kasan-dev@googlegroups.com>; Wed, 25 Sep 2019 05:12:10 -0700 (PDT)
X-Received: by 2002:a2e:a316:: with SMTP id l22mr6207823lje.211.1569413529490;
 Wed, 25 Sep 2019 05:12:09 -0700 (PDT)
MIME-Version: 1.0
References: <1548057848-15136-1-git-send-email-rppt@linux.ibm.com> <CAHCN7x+Jv7yGPoB0Gm=TJ30ObLJduw2XomHkd++KqFEURYQcGg@mail.gmail.com>
In-Reply-To: <CAHCN7x+Jv7yGPoB0Gm=TJ30ObLJduw2XomHkd++KqFEURYQcGg@mail.gmail.com>
From: Fabio Estevam <festevam@gmail.com>
Date: Wed, 25 Sep 2019 09:12:18 -0300
Message-ID: <CAOMZO5A_U4aYC4XZXK1r9JaLg-eRdXy8m6z4GatQp62rK4HZ6A@mail.gmail.com>
Subject: Re: [PATCH v2 00/21] Refine memblock API
To: Adam Ford <aford173@gmail.com>
Cc: Mike Rapoport <rppt@linux.ibm.com>, Rich Felker <dalias@libc.org>, linux-ia64@vger.kernel.org, 
	Petr Mladek <pmladek@suse.com>, linux-sh@vger.kernel.org, 
	Catalin Marinas <catalin.marinas@arm.com>, Heiko Carstens <heiko.carstens@de.ibm.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Max Filippov <jcmvbkbc@gmail.com>, 
	Guo Ren <guoren@kernel.org>, Michael Ellerman <mpe@ellerman.id.au>, sparclinux@vger.kernel.org, 
	Christoph Hellwig <hch@lst.de>, linux-s390@vger.kernel.org, linux-c6x-dev@linux-c6x.org, 
	Yoshinori Sato <ysato@users.sourceforge.jp>, Richard Weinberger <richard@nod.at>, x86@kernel.org, 
	Russell King <linux@armlinux.org.uk>, kasan-dev <kasan-dev@googlegroups.com>, 
	Geert Uytterhoeven <geert@linux-m68k.org>, Mark Salter <msalter@redhat.com>, 
	Dennis Zhou <dennis@kernel.org>, Matt Turner <mattst88@gmail.com>, 
	linux-snps-arc@lists.infradead.org, uclinux-h8-devel@lists.sourceforge.jp, 
	devicetree <devicetree@vger.kernel.org>, linux-xtensa@linux-xtensa.org, 
	linux-um@lists.infradead.org, 
	The etnaviv authors <etnaviv@lists.freedesktop.org>, linux-m68k@lists.linux-m68k.org, 
	Rob Herring <robh+dt@kernel.org>, Greentime Hu <green.hu@gmail.com>, xen-devel@lists.xenproject.org, 
	Stafford Horne <shorne@gmail.com>, Guan Xuetao <gxt@pku.edu.cn>, 
	arm-soc <linux-arm-kernel@lists.infradead.org>, Michal Simek <monstr@monstr.eu>, 
	Tony Luck <tony.luck@intel.com>, Linux Memory Management List <linux-mm@kvack.org>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, USB list <linux-usb@vger.kernel.org>, 
	linux-mips@vger.kernel.org, Paul Burton <paul.burton@mips.com>, 
	Vineet Gupta <vgupta@synopsys.com>, linux-alpha@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, linuxppc-dev@lists.ozlabs.org, 
	"David S. Miller" <davem@davemloft.net>, openrisc@lists.librecores.org, 
	Chris Healy <cphealy@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: festevam@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=e0naPQpn;       spf=pass
 (google.com: domain of festevam@gmail.com designates 2a00:1450:4864:20::243
 as permitted sender) smtp.mailfrom=festevam@gmail.com;       dmarc=pass
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

Hi Adam,

On Wed, Sep 25, 2019 at 6:38 AM Adam Ford <aford173@gmail.com> wrote:

> I know it's rather late, but this patch broke the Etnaviv 3D graphics
> in my i.MX6Q.
>
> When I try to use the 3D, it returns some errors and the dmesg log
> shows some memory allocation errors too:
> [    3.682347] etnaviv etnaviv: bound 130000.gpu (ops gpu_ops)
> [    3.688669] etnaviv etnaviv: bound 134000.gpu (ops gpu_ops)
> [    3.695099] etnaviv etnaviv: bound 2204000.gpu (ops gpu_ops)
> [    3.700800] etnaviv-gpu 130000.gpu: model: GC2000, revision: 5108
> [    3.723013] etnaviv-gpu 130000.gpu: command buffer outside valid
> memory window
> [    3.731308] etnaviv-gpu 134000.gpu: model: GC320, revision: 5007
> [    3.752437] etnaviv-gpu 134000.gpu: command buffer outside valid
> memory window

This looks similar to what was reported at:
https://bugs.freedesktop.org/show_bug.cgi?id=111789

Does it help if you use the same suggestion and pass cma=256M in your
kernel command line?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAOMZO5A_U4aYC4XZXK1r9JaLg-eRdXy8m6z4GatQp62rK4HZ6A%40mail.gmail.com.

Return-Path: <kasan-dev+bncBD2NJ5WGSUOBB6M5YOKAMGQEF2OJCTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x638.google.com (mail-ej1-x638.google.com [IPv6:2a00:1450:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id AE65653633B
	for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 15:15:38 +0200 (CEST)
Received: by mail-ej1-x638.google.com with SMTP id p7-20020a170906614700b006f87f866117sf2376628ejl.21
        for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 06:15:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653657338; cv=pass;
        d=google.com; s=arc-20160816;
        b=Wnu3eyVsb0n62Grcg8/QEO365w/0L8ZkxFo6u5gPOM85t4/OO36RJ8cVMKNfM3UUp2
         U302JNSy9GA3gAxl+aZojPpotdyVTPSndKkBU1cjWcYYEUbazYhHomZBnj27d/IfLV/h
         /fbr/Kd2dSU+Gwm3vpImF30SUjdxw5sQvhAAu3jUn0Emd2kth2Piz569MaZReW1iAtki
         TM9uhlMyjYgrDdxA3Z8HSmsIBAtd32fkeQtcxeToyguO7FbTESpJkYRzRgyCXdHhyyyc
         Rl/7cunlgkLgfSnVoyHCsh2Lk05WPhueXHLeeuwm4ZrZ8Qh7uxQqwADtOcOYc2ha1/PX
         QkFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=MPYqc79mUYL5CPfs0pJlAOvHbJvKQkQ4qoC1Kme234g=;
        b=aUZpdyyPEKkTkcss7rsruuwzFWJiwIx0BG8UTny4Wq/7kikJIrcShyrF0BVmayIJ0G
         xForBbAWaYt3SVUO5q4JHmRPWb6K5gN5pNWlTALum+uozPNJFTf67wjf6Q4v7OxckoRX
         zmd6c6IVd98cqOcnioeXb5brFbBX/z4lycW4ngn3V8el70OTOckfoRyteLowPNcFI+Iw
         Csrtd7e4cT+zXz2oPMDTBu4Jnne5MMkSTxXh7PJVHVq4XR9g27/ETLDz5jaT52N3fbWl
         XHUR6WqQNWFnAUny7O7/riUk6s8HnQz3GtTuvnbSuUDiqfhLXPg83L8z9My3p808p+gI
         y29A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=dNdWEPX6;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MPYqc79mUYL5CPfs0pJlAOvHbJvKQkQ4qoC1Kme234g=;
        b=md0ICCJAWLkbG5+8izHdGw/M+3OyhGkVj7AyVr6lIbUBajX+CKyVb6KaB8HsLgWIJO
         DNnI9SL6q5zj2RxkpU/9fBPCcfo1/QflsKj2M4fTij0wBYyYBsL9wyeVKASt/X3v/W9n
         gCn7QiQpuO7GtyT6Eh146X2Og9Hvhltvj1SuqWtgnyFRekznBxCJhj9kJyD306yL61c+
         GiReXaskNhDwJ8/wx038BEuHKp1LfxQYOuWtq+MeyuC/PL46Qm5GC7jdNx+VjPojddUz
         YcO81iNkJUSmDxCQje2nUy6YtVtKgwVMP4H5CcqcLx9II3To0SwmsTvbEv6CaVzjg+sM
         6QOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MPYqc79mUYL5CPfs0pJlAOvHbJvKQkQ4qoC1Kme234g=;
        b=MZ+lzR8alR2qc664hmbOboZEEYUIToECkxQ2DKuTwSer2pZao2svEQragTQxcF1bxw
         NNQUAP+FKS8UoPnfrFRepdTH7GqAMgi4c6/MP05jSIdHq0AcDzpttP/FLR3SSSxjBykU
         6TnMMuZLmYcEJapL2WR1oFfu2EAEsPAt7Kyq9BK5LlWiUc6qdd56aE9EQyNIp/gNlZ0C
         gQBT+/9xx5KwNeJS+NOvgpljInUuXCxEYJWG+wrkAQuBPYbFnjkMoQ+W/OUZiRfQPMCe
         DYY+v3WhgWWgcmllk9hxyE+W21jsnV28G0FBlrKQnggGeDvGJzps/HkM7faECFwBjQNF
         QP+Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532OxZt/AAnpLfJC7ocl8+zOtziKrVQKkGhVi9ju2oDiuyA7FTun
	mm/1OFMT+dI3/7KtfzXwtnY=
X-Google-Smtp-Source: ABdhPJx6CpeTxI5f75hc6z3FVRm7Cm57v0F5ltPFdvKqNs+NXVzbnLgmjQdPIgA1oXsJEtehkYZAmA==
X-Received: by 2002:a17:907:60d0:b0:6fe:b0af:2fda with SMTP id hv16-20020a17090760d000b006feb0af2fdamr31038230ejc.357.1653657338152;
        Fri, 27 May 2022 06:15:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:3fc5:b0:6fe:fc5b:a579 with SMTP id
 k5-20020a1709063fc500b006fefc5ba579ls4643291ejj.10.gmail; Fri, 27 May 2022
 06:15:37 -0700 (PDT)
X-Received: by 2002:a17:907:7284:b0:6ff:16b8:3073 with SMTP id dt4-20020a170907728400b006ff16b83073mr10968770ejc.196.1653657337261;
        Fri, 27 May 2022 06:15:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653657337; cv=none;
        d=google.com; s=arc-20160816;
        b=PS9WNPQW0CYFz1DEtspJRrldByba2P+ep6JYIyBelDkraeCHoKye6mReRjle4+5Ki3
         31Jr2bpJ0pISrI1pP4rUCY1oDT0MY3O5UaCDqT2Y4SdMiZ6tUPYe4bSysFiYSfUSJZdO
         0kyqJfIPoHezGYp6yTnjO48aeqbMGVvqhp3Dwu/ZptphyxJr+dP1yvkIA1ejYmpJTgLf
         BznS9fQtRI8fgOilpW5/fxt+JVrkMXX705BhzRbtwa/DZ0jdvcFJepj3XNJkhuM7u2hA
         wOQNQxhLy0+15HWJOHmRThcFL8YsK2WyU9W61FrOfpakthkg952wLghBqPLV8mGaxRSj
         pTDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=okBy2z0SI8JCqUVCUlOTjpJ/WMcl6Mo/G8RcOliMI6k=;
        b=stt3fZXBbpww1h2yqa/4TQRR0W7MMJ7G6bjy+TE33Yns0ZdPkjKqB1Zy4IQqbPjWXa
         Qvo+lcNyfYl8ZZTYzS+qakdN3UAez+rfyjAq61a2PdbHC/vRa9QF+/l9rpU4NGNVYiR4
         7cqHZLE4gMGtz0dJYb4CWtz4oQta/Sw/F35kenx5QD6y9h+58ZuRanjgNwOSnz8Si6K8
         EwosVRmr4cBmc4/bOkeVA+EbRELwiXdevETPZ7ceDZfCEchhI6SR1MBecaqiylLyLgAZ
         /QCgmdhm6vtFcRPaJ8rqIycnR+fdt47JYQZ1eilvSZ3RPbiXSwf3dQ7V0gOGkrb7Zedf
         aQKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=dNdWEPX6;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:191:4433::2])
        by gmr-mx.google.com with ESMTPS id j25-20020a056402239900b0041cf5333d81si194583eda.4.2022.05.27.06.15.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 27 May 2022 06:15:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) client-ip=2a01:4f8:191:4433::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.95)
	(envelope-from <johannes@sipsolutions.net>)
	id 1nuZoU-0063Iv-Di;
	Fri, 27 May 2022 15:15:34 +0200
Message-ID: <6fa1ebe49b8d574fb1c82aefeeb54439d9c98750.camel@sipsolutions.net>
Subject: Re: [RFC PATCH v3] UML: add support for KASAN under x86_64
From: Johannes Berg <johannes@sipsolutions.net>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: David Gow <davidgow@google.com>, Vincent Whitchurch
 <vincent.whitchurch@axis.com>, Patricia Alfonso <trishalfonso@google.com>, 
 Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>,
 anton.ivanov@cambridgegreys.com,  Brendan Higgins
 <brendanhiggins@google.com>, kasan-dev <kasan-dev@googlegroups.com>,
 linux-um@lists.infradead.org,  LKML <linux-kernel@vger.kernel.org>, Daniel
 Latypov <dlatypov@google.com>
Date: Fri, 27 May 2022 15:15:33 +0200
In-Reply-To: <CACT4Y+ZVrx9VudKV5enB0=iMCBCEVzhCAu_pmxBcygBZP_yxfg@mail.gmail.com>
References: <20220525111756.GA15955@axis.com>
	 <20220526010111.755166-1-davidgow@google.com>
	 <e2339dcea553f9121f2d3aad29f7428c2060f25f.camel@sipsolutions.net>
	 <CACT4Y+ZVrx9VudKV5enB0=iMCBCEVzhCAu_pmxBcygBZP_yxfg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.44.1 (3.44.1-1.fc36)
MIME-Version: 1.0
X-malware-bazaar: not-scanned
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sipsolutions.net header.s=mail header.b=dNdWEPX6;       spf=pass
 (google.com: domain of johannes@sipsolutions.net designates
 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
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

On Fri, 2022-05-27 at 15:09 +0200, Dmitry Vyukov wrote:
> > I did note (this is more for kasan-dev@) that the "freed by" is fairly
> > much useless when using kfree_rcu(), it might be worthwhile to annotate
> > that somehow, so the stack trace is recorded by kfree_rcu() already,
> > rather than just showing the RCU callback used for that.
> 
> KASAN is doing it for several years now, see e.g.:
> https://groups.google.com/g/syzkaller-bugs/c/eTW9zom4O2o/m/_v7cOo2RFwAJ
> 

Hm. It didn't for me:

> BUG: KASAN: use-after-free in ieee80211_vif_use_reserved_context+0x32d/0x40f [mac80211]
> Read of size 4 at addr 0000000065c73340 by task kworker/u2:1/17

Yes.

> CPU: 0 PID: 17 Comm: kworker/u2:1 Tainted: G           O      5.18.0-rc1 #5
> Workqueue: phy0 ieee80211_chswitch_work [mac80211]
> Stack:
>  60ba783f 00000000 10000c268f4e 60ba783f
>  60e60847 70dc9928 719f6e99 00000000
>  71883b20 60bb0b42 60bb0b19 65c73340
> Call Trace:
>  [<600447ea>] show_stack+0x13e/0x14d
>  [<60bb0b42>] dump_stack_lvl+0x29/0x2e
>  [<602ef7c0>] print_report+0x15d/0x60b
>  [<602efdc0>] kasan_report+0x98/0xbd
>  [<602f0cc2>] __asan_report_load4_noabort+0x1b/0x1d
>  [<719f6e99>] ieee80211_vif_use_reserved_context+0x32d/0x40f [mac80211]

This is the user, it just got freed during a function call a few lines
up.

> Allocated by task 16:
>  save_stack_trace+0x2e/0x30
>  stack_trace_save+0x81/0x9b
>  kasan_save_stack+0x2d/0x54
>  kasan_set_track+0x34/0x3e
>  ____kasan_kmalloc+0x8d/0x99
>  __kasan_kmalloc+0x10/0x12
>  __kmalloc+0x1f6/0x20b
>  ieee80211_alloc_chanctx+0xdc/0x35f [mac80211]

This makes sense too.

> Freed by task 8:
>  save_stack_trace+0x2e/0x30
>  stack_trace_save+0x81/0x9b
>  kasan_save_stack+0x2d/0x54
>  kasan_set_track+0x34/0x3e
>  kasan_set_free_info+0x33/0x44
>  ____kasan_slab_free+0x12b/0x149
>  __kasan_slab_free+0x19/0x1b
>  slab_free_freelist_hook+0x10b/0x16a
>  kfree+0x10d/0x1fa
>  kvfree+0x38/0x3a
>  rcu_process_callbacks+0x2c5/0x349

This is the RCU callback.

> Last potentially related work creation:
>  save_stack_trace+0x2e/0x30
>  stack_trace_save+0x81/0x9b
>  kasan_save_stack+0x2d/0x54
>  __kasan_record_aux_stack+0xd5/0xe2
>  kasan_record_aux_stack_noalloc+0x12/0x14
>  insert_work+0x50/0xd7
>  __queue_work+0x805/0x95c
>  queue_work_on+0xba/0x131
>  call_usermodehelper_exec+0x242/0x361
>  kobject_uevent_env+0xe46/0xeaf
>  kobject_uevent+0x12/0x14
>  driver_register+0x37e/0x38d
>  pcie_port_service_register+0x19d/0x1a5

This stuff is completely unrelated.

> The buggy address belongs to the object at 0000000065c73300
>  which belongs to the cache kmalloc-192 of size 192
> The buggy address is located 64 bytes inside of
>  192-byte region [0000000065c73300, 0000000065c733c0)
> 

and that's it?

johannes

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6fa1ebe49b8d574fb1c82aefeeb54439d9c98750.camel%40sipsolutions.net.

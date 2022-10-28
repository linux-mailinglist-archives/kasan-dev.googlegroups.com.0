Return-Path: <kasan-dev+bncBAABBDM652NAMGQEOJU72WY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113b.google.com (mail-yw1-x113b.google.com [IPv6:2607:f8b0:4864:20::113b])
	by mail.lfdr.de (Postfix) with ESMTPS id EA71C610BF4
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Oct 2022 10:13:02 +0200 (CEST)
Received: by mail-yw1-x113b.google.com with SMTP id 00721157ae682-3697bd55974sf38281937b3.15
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Oct 2022 01:13:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666944781; cv=pass;
        d=google.com; s=arc-20160816;
        b=HaPAk30x38i2nTpdGsgEjO+PG+MHAInZyglaRWfaMjkzvNaO71g+f2o1UQKrZSk44i
         libyAsLMNV9T/OcNfRuZkmtuWT/X77pGiC8UqlJczRnZWrshJ3bv+sdum+paFJkahYdJ
         qnwrp7O5wgZRQ+UDJqS1C8cBbcwMp8m1A+8ItS9kBA6WZIGmL8wmgHUjTcbUw7EbiCz/
         3gO74zGhDRwt1weF9OT496wczC0lXIn7ADv5RYHiqw5e7tFmW+4Cx+kjtYD2VPhDPR00
         xm/mOArfjUlDeodvt7Zi/4ijDXlvgBFAs+Ln8U0VCzt0Lx6TdToJEcHUhWb1aDGwaABE
         eUrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:organization:references:cc:to:from:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=wEuMs2udeZ2ZijrShSWp+pAVd3T7WWEvJ/1Nk9cjh8Q=;
        b=Hsda/vhdO6teddrlT3poNJxTapugafYgXP2Pzo5llmqtQkwpJ3ZTCt3jiRkENWCILB
         Mt7b1x7S2fLDvhKbencjSykMYDyYDBFT6dTfWBKoCrY6oY4pMFuzT4oGZ3S2MnCCb0fR
         HPfNHfEGgzjCKVNQSrN+AqiBNPX/WRFuFEN1jXnesb3RlYYhO68YiuZyYFePVjHh720v
         QkH1s825y9yLIZGoL1Y47WdiUE5G5aN/cRzsOoyqbuJHfb5AwfcToih8N2Mbg+Plz1rd
         hQR3g/uPD0/Ar4NIBeMQHC/8++ceFO4U8BFN9fw3jTMjnbm5qoxbMoalU1AchIRBb7A6
         Ga9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of zhongbaisong@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=zhongbaisong@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:organization:references:cc:to
         :from:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wEuMs2udeZ2ZijrShSWp+pAVd3T7WWEvJ/1Nk9cjh8Q=;
        b=DNJ3uxDn/tZo5qgpqpXOh+4jvCKVgsHviQ7TC1XRmslWUm+rjIYSG6R8oYU71mvXK2
         eI+O/o5HW6Z5HChezfUIoAT0zPb2NOfjyXxDNs9w4ryea0VbOaqvhwVoHq9ndyyHVxHh
         RTEP39gAP4d7x3OXWTb/WaZcrvEyxPZ5p9Qsx4uO0UeI9ev4xKXZsTbEJRCoU1mrOO9r
         X6/dzMAM4u2EeWNcchFH/hYsJwX/SXarc5kn5A9gQpnzfZDJNd5aXjIopMAOXBldSwCk
         Itv7ZB5tcHpUaEsufSk4fFU4NHBttAEvaTT3KAwauju9CZ5WMoSo2O7I5OCjddIlZRi4
         6TDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:organization:references:cc:to
         :from:subject:user-agent:mime-version:date:message-id
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=wEuMs2udeZ2ZijrShSWp+pAVd3T7WWEvJ/1Nk9cjh8Q=;
        b=nzcj8SXpiwkLJ4Y4yDFho/x2C3EUmPK5fLpAMeMDEEKfTPrQjPFWF2qy5vho7fs+zm
         vs6Pmf9+Up1fcUN0W0AQ36c4qBpSGL7yTRubzYFeC7M5+1K1rzjytpWBp2YjCRlEg8fI
         /VfatNG+m1CZ4fMin9LfvSBntgtegw3h+GiGfJ848GlMuXben3TSnGw60PAd4k5GZh9h
         6qna0lXLyuNaCQFA9Y9TIw+0MOcd4iQ4OpQE4u2s48q+1Ze7DPHDBUeA4AhajehenyPt
         FCqFGBTZGz0jYuKzf76mWZRjuFUkg1X9JWAIrZ41SXizean7v6J47s2ptOUunupwd29b
         sQ5g==
X-Gm-Message-State: ACrzQf3umy/7yfAAMQ3wxFf6QhgctzRRsj89u+enHTnlGHcnLMis1nLv
	MPD1fy1kNgvcn8h2PbOIgSM=
X-Google-Smtp-Source: AMsMyM575nX8MhJpO4n3D2yOUH9xmM2RIKlKvHP2VrbgKqbzmRivivbqQs565DSkeaL5eqp5BR969Q==
X-Received: by 2002:a81:4805:0:b0:36b:d77e:54cf with SMTP id v5-20020a814805000000b0036bd77e54cfmr27855478ywa.196.1666944781682;
        Fri, 28 Oct 2022 01:13:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:aaf0:0:b0:6cb:d428:7c50 with SMTP id t103-20020a25aaf0000000b006cbd4287c50ls1033355ybi.4.-pod-prod-gmail;
 Fri, 28 Oct 2022 01:13:01 -0700 (PDT)
X-Received: by 2002:a25:6647:0:b0:6cb:8601:238a with SMTP id z7-20020a256647000000b006cb8601238amr15445472ybm.598.1666944781120;
        Fri, 28 Oct 2022 01:13:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666944781; cv=none;
        d=google.com; s=arc-20160816;
        b=DaugMo+ZjI7eCTfV5IWc43DMDU1knSFJye11VX5t4FFvl1UcnWzbHTo6X13JNzDKOd
         vgCNEKcncU5tG4a8wJxqtkr+JIwtDwfbyOfysmfox+fIa+D7aq/P7fA9fBYLKEY9hflF
         DAjLrObboSDaERh1uoPuy1akc9EAeJzN1xJe/2wp2dh+XwXy8iNFlo6MaQtxEk/k1bzr
         U6W3NzbpJLkNenrfae/4RlYtrTRRSYRVprbJcqFo01t+DvtCXYvKD91EysJVkBeRBj7K
         y4cT8P6S2m89MxGa3B/rfJaHLXrYcMcWtQDHyWRN27UWOGVFG6RmWzO6oY8YJ/dbJH2/
         r26A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:organization:references:cc:to
         :from:subject:user-agent:mime-version:date:message-id;
        bh=1dcOe4NASk7flqWAdelmeSOXdJRegiUp+wZDBLy8Jb8=;
        b=PR0F6h2ObtP4HgJs9q1Y9igFiSCNgAXT3Fxaiy5ymW/CHr8rMQjLaG61/KsQ68IRoq
         pTwr+qdBC6ocsKX7QY3L/bxCMkilDGvz0+xqiK8Ae7AH405xmM0v57OaZEjJ+ni7xJSb
         9y5R32duB/7/OWQJvdHjusy1RPEiJEHa0cYkG/i7cp/bRZD2mhQeqA7peuYSfmwuthsl
         wLCI76YjTpJMeeU/Xmo+EMNxaj2PIsV+8OMC2jyXq9pHxBDZJrSOnDlIZRIfY16+y+DR
         Ryf3R4Q1NVCcWQoSeKagwfG77Ud0eFz8LtpxI/Vyw3FjH+1iHbCDAVfdkl7L+FnRY8Tn
         /n+A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of zhongbaisong@huawei.com designates 45.249.212.189 as permitted sender) smtp.mailfrom=zhongbaisong@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga03-in.huawei.com (szxga03-in.huawei.com. [45.249.212.189])
        by gmr-mx.google.com with ESMTPS id bh24-20020a05690c039800b0035786664d22si188197ywb.1.2022.10.28.01.13.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 28 Oct 2022 01:13:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhongbaisong@huawei.com designates 45.249.212.189 as permitted sender) client-ip=45.249.212.189;
Received: from canpemm500005.china.huawei.com (unknown [172.30.72.57])
	by szxga03-in.huawei.com (SkyGuard) with ESMTP id 4MzFb54yzbzFq4p;
	Fri, 28 Oct 2022 16:10:09 +0800 (CST)
Received: from [10.174.178.197] (10.174.178.197) by
 canpemm500005.china.huawei.com (7.192.104.229) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2375.31; Fri, 28 Oct 2022 16:12:57 +0800
Message-ID: <41fa7ae0-d09a-659b-82ea-28036c02beee@huawei.com>
Date: Fri, 28 Oct 2022 16:12:56 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.4.1
Subject: Re: [PATCH -next] selftests/bpf: fix alignment problem in
 bpf_prog_test_run_skb()
From: "'zhongbaisong' via kasan-dev" <kasan-dev@googlegroups.com>
To: <elver@google.com>, <glider@google.com>, <catalin.marinas@arm.com>,
	<will@kernel.org>, <wangkefeng.wang@huawei.com>,
	<linux-kernel@vger.kernel.org>, <edumazet@google.com>, <kuba@kernel.org>,
	<pabeni@redhat.com>, <davem@davemloft.net>, <catalin.marinas@arm.com>,
	<will@kernel.org>, <mark.rutland@arm.com>, <dvyukov@google.com>
CC: <netdev@vger.kernel.org>, <bpf@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, Linux MM <linux-mm@kvack.org>
References: <a3552059-89d4-1866-a141-6de9454f8116@huawei.com>
Organization: huawei
In-Reply-To: <a3552059-89d4-1866-a141-6de9454f8116@huawei.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.174.178.197]
X-ClientProxiedBy: dggems702-chm.china.huawei.com (10.3.19.179) To
 canpemm500005.china.huawei.com (7.192.104.229)
X-CFilter-Loop: Reflected
X-Original-Sender: zhongbaisong@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of zhongbaisong@huawei.com designates 45.249.212.189 as
 permitted sender) smtp.mailfrom=zhongbaisong@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: zhongbaisong <zhongbaisong@huawei.com>
Reply-To: zhongbaisong <zhongbaisong@huawei.com>
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

Sorry, Pls drop this.

On 2022/10/28 15:01, zhongbaisong wrote:
> We observed a crash "KFENCE: use-after-free in __skb_clone" during fuzzin=
g.
> It's a frequent occurrance in aarch64 and the codepath is always the=20
> same,but cannot be reproduced in x86_64.
> The config and reproducer are in the attachement.
> Detailed crash information is as follows.
>=20
> -----------------------------------------
>  =C2=A0BUG: KFENCE: use-after-free read in __skb_clone+0x214/0x280
>=20
>  =C2=A0Use-after-free read at 0xffff00022250306f (in kfence-#250):
>  =C2=A0 __skb_clone+0x214/0x280
>  =C2=A0 skb_clone+0xb4/0x180
>  =C2=A0 bpf_clone_redirect+0x60/0x190
>  =C2=A0 bpf_prog_207b739f41707f89+0x88/0xb8
>  =C2=A0 bpf_test_run+0x2dc/0x4fc
>  =C2=A0 bpf_prog_test_run_skb+0x4ac/0x7d0
>  =C2=A0 __sys_bpf+0x700/0x1020
>  =C2=A0 __arm64_sys_bpf+0x4c/0x60
>  =C2=A0 invoke_syscall+0x64/0x190
>  =C2=A0 el0_svc_common.constprop.0+0x88/0x200
>  =C2=A0 do_el0_svc+0x3c/0x50
>  =C2=A0 el0_svc+0x68/0xd0
>  =C2=A0 el0t_64_sync_handler+0xb4/0x130
>  =C2=A0 el0t_64_sync+0x16c/0x170
>=20
>  =C2=A0kfence-#250: 0xffff000222503000-0xffff00022250318e, size=3D399,=20
> cache=3Dkmalloc-512
>=20
>  =C2=A0allocated by task 2970 on cpu 0 at 65.981345s:
>  =C2=A0 bpf_test_init.isra.0+0x68/0x100
>  =C2=A0 bpf_prog_test_run_skb+0x114/0x7d0
>  =C2=A0 __sys_bpf+0x700/0x1020
>  =C2=A0 __arm64_sys_bpf+0x4c/0x60
>  =C2=A0 invoke_syscall+0x64/0x190
>  =C2=A0 el0_svc_common.constprop.0+0x88/0x200
>  =C2=A0 do_el0_svc+0x3c/0x50
>  =C2=A0 el0_svc+0x68/0xd0
>  =C2=A0 el0t_64_sync_handler+0xb4/0x130
>  =C2=A0 el0t_64_sync+0x16c/0x170
>=20
>  =C2=A0CPU: 0 PID: 2970 Comm: syz Tainted: G=C2=A0=C2=A0=C2=A0 B=C2=A0=C2=
=A0 W 6.1.0-rc2-next-20221025=20
> #140
>  =C2=A0Hardware name: linux,dummy-virt (DT)
>  =C2=A0pstate: 60400005 (nZCv daif +PAN -UAO -TCO -DIT -SSBS BTYPE=3D--)
>  =C2=A0pc : __skb_clone+0x214/0x280
>  =C2=A0lr : __skb_clone+0x208/0x280
>  =C2=A0sp : ffff80000fc37630
>  =C2=A0x29: ffff80000fc37630 x28: ffff80000fc37bd0 x27: ffff80000fc37720
>  =C2=A0x26: ffff000222503000 x25: 000000000000028f x24: ffff0000d0898d5c
>  =C2=A0x23: ffff0000d08997c0 x22: ffff0000d089977e x21: ffff00022250304f
>  =C2=A0x20: ffff0000d0899700 x19: ffff0000d0898c80 x18: 0000000000000000
>  =C2=A0x17: ffff800008379bbc x16: ffff800008378ee0 x15: ffff800008379bbc
>  =C2=A0x14: ffff800008378ee0 x13: 0040004effff0008 x12: ffff6000444a060f
>  =C2=A0x11: 1fffe000444a060e x10: ffff6000444a060e x9 : dfff800000000000
>  =C2=A0x8 : ffff000222503072 x7 : 00009fffbbb5f9f3 x6 : 0000000000000002
>  =C2=A0x5 : ffff00022250306f x4 : ffff6000444a060f x3 : ffff8000096fb2a8
>  =C2=A0x2 : 0000000000000001 x1 : ffff00022250306f x0 : 0000000000000001
>  =C2=A0Call trace:
>  =C2=A0 __skb_clone+0x214/0x280
>  =C2=A0 skb_clone+0xb4/0x180
>  =C2=A0 bpf_clone_redirect+0x60/0x190
>  =C2=A0 bpf_prog_207b739f41707f89+0x88/0xb8
>  =C2=A0 bpf_test_run+0x2dc/0x4fc
>  =C2=A0 bpf_prog_test_run_skb+0x4ac/0x7d0
>  =C2=A0 __sys_bpf+0x700/0x1020
>  =C2=A0 __arm64_sys_bpf+0x4c/0x60
>  =C2=A0 invoke_syscall+0x64/0x190
>  =C2=A0 el0_svc_common.constprop.0+0x88/0x200
>  =C2=A0 do_el0_svc+0x3c/0x50
>  =C2=A0 el0_svc+0x68/0xd0
>  =C2=A0 el0t_64_sync_handler+0xb4/0x130
>  =C2=A0 el0t_64_sync+0x16c/0x170
>=20
>=20
>  From the crash info, I found the problem happend at=20
> atomic_inc(&(skb_shinfo(skb)->dataref)) in __skb_clone().
>=20
>  =C2=A0=C2=A0=C2=A0 static struct sk_buff *__skb_clone(struct sk_buff *n,=
 struct=20
> sk_buff *skb)
>  =C2=A0=C2=A0=C2=A0 {
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ...
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 refcount_set(&n->users, 1);
>=20
>  >=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 atomic_inc(&(skb_shinfo(skb)->data=
ref));
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 skb->cloned =3D 1;
>=20
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return n;
>  =C2=A0=C2=A0=C2=A0 #undef C
>  =C2=A0=C2=A0=C2=A0 }
>=20
>=20
> when KENCE UAF happend, the address of skb_shinfo(skb) always end with=20
> 0xf=EF=BC=8Clike
> 0xffff0002224f104f, 0xffff0002224f304f, etc.
>=20
> But when KFENCE is not working, the address of skb_shinfo(skb) always=20
> end with 0xc0, like
> 0xffff0000d7e908c0, 0xffff0000d682f4c0, ect.
>=20
> So, I guess the problem is related to kfence memory address alignment in=
=20
> aarch64.
> In bpf_prog_test_run_skb(), I try to let the 'size' align with=20
> SMP_CACHE_BYTES to fix that.
>=20
> After that, the KENCE user-after-free disappeared.
>=20
> Fixes: be3d72a2896c ("bpf: move user_size out of bpf_test_init")
> Signed-off-by: Baisong Zhong <zhongbaisong@huawei.com>
> ---
>  =C2=A0net/bpf/test_run.c | 2 ++
>  =C2=A01 file changed, 2 insertions(+)
>=20
> diff --git a/net/bpf/test_run.c b/net/bpf/test_run.c
> index 13d578ce2a09..3414aa2930d4 100644
> --- a/net/bpf/test_run.c
> +++ b/net/bpf/test_run.c
> @@ -1096,6 +1096,8 @@ int bpf_prog_test_run_skb(struct bpf_prog *prog,=20
> const union bpf_attr *kattr,
>  =C2=A0=C2=A0=C2=A0 if (kattr->test.flags || kattr->test.cpu || kattr->te=
st.batch_size)
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return -EINVAL;
>=20
> +=C2=A0=C2=A0 size =3D SKB_DATA_ALIGN(size);
> +
>  =C2=A0=C2=A0=C2=A0 data =3D bpf_test_init(kattr, kattr->test.data_size_i=
n,
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 size, NET_SKB_PAD + NET_IP_ALIGN,
>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 SKB_DATA_ALIGN(sizeof(struct skb_shared_info)));
> --=20
> 2.25.1
>=20
> .
>=20
>=20
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/41fa7ae0-d09a-659b-82ea-28036c02beee%40huawei.com.

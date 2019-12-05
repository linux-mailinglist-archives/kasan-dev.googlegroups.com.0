Return-Path: <kasan-dev+bncBCFYN6ELYIORBSFQUPXQKGQEEO554AA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 7EA21113F20
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Dec 2019 11:13:30 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id x189sf1553964pgd.9
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Dec 2019 02:13:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575540808; cv=pass;
        d=google.com; s=arc-20160816;
        b=S+S2rMtbOh8/8i+DzswaF15yOARH/Wh0Jgc9dJLg2SZ5aRzgS61BYN+dq++E6FFcU5
         GI9YXyVtehxP+iZns9622jopKkfU181puySbcpJZju5/63GRHPDDmbTJeUW9umllQf3j
         bhBTLlYi2TsKLDhkGhpDmJbqwU/tFXkPjDleTsvbjjfcouyZwtgsAmAKY/U7mkGV/GNa
         DSe+AK13NdfRrzj2YlGSBvUeBti+Y3O6qCuIcP0jJJKor8k9nDp5pVeUO5i+nAcUydFy
         qclUXlDvwGYKnQDBzWdWL2R8wTjUUtIwsr5mtKgSJU0WWOkrD2msHYyDCWc8P9D6B0l6
         OlvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:to:subject:sender:dkim-signature;
        bh=oSarWD2GXYIH3RQQDdigzhYYSyJKPuHx8Q7wqf12y7Y=;
        b=EgfaLUEQDkdziXVpUE0xqdB7oCpynvm9A36kBnQQJgBJ5P0zSeLwLEkxdd933Ds82R
         SIvuG4dTcvqz70uRiNX6OqcGb2K4C5cNm6CpvHkIvEVaMactZtXRTI0kZARZ3yu2YkrK
         5HIe0iOQrNPNny/dnRJcACwG7xE282JDzYsbernU7tQJx/asnr1j4LyXUhpsNe738IfS
         uZOupPpDx2nsjZoRROh0lATgSqbtfZTX5cwU2/xC6mmgclwpp+u/ZGQ3lhN1ny5Q6Ji0
         vl60lOodRpWKE9FJbP68wz1IZZmU22JVAIUy1dNmzodng0l/2A4p20Z9ubQDRIctkqFL
         pwJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=caA7vTLu;
       spf=pass (google.com: domain of pbonzini@redhat.com designates 205.139.110.61 as permitted sender) smtp.mailfrom=pbonzini@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oSarWD2GXYIH3RQQDdigzhYYSyJKPuHx8Q7wqf12y7Y=;
        b=i6/xHJl1C86vREcwWL3S1iQOr7jdjibYllmXyiB/kOJbUeH0KpALIpsX0XAZCn87Mb
         WcEVPo6XScm3FNdjDcORJM8W87/QLwQzrud45ULKAvkVb6k2NPd1MGjpNbsenvYXWjcE
         NrWgCueqTK5lBAlhe02CJLJRxCZBMEFIBiC0oG/rOKoBeesui30qqI73LW03wQC3E4+Q
         5dpnhCg6ncS9H6wonn8m7bcUKAd8MySbFwb+iRLHOoA9T7JHLxFHFV/YEJKG0M0LTsQ+
         F+XjEpKPCh/VFkmVKkDPHP3YiRvdLmc2a/FXKLiWRY04hVv1tehFk0QtJgmbIccW2876
         gQtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oSarWD2GXYIH3RQQDdigzhYYSyJKPuHx8Q7wqf12y7Y=;
        b=EqjeWp2gincuajFnNzykg2LYoXepXus8bXUvdt0pZ8WpkGkkVHbDHuMPXNjeVPklQg
         nAsIJZh9LNCTv1y1uo9aNIKFWb//qGlSQYPxBijNJIMfmn3wWRORbcLD+egwf3k1wHpt
         nc2p5yNReBCxdodrLciSXvLme1Iw9BjEjjw/ctYgkPht3hYlW+RZuN2moMBj3MrmcWN7
         gKu+V5Yc955nvmUZ0dNMT5azJeFZUDVSEGfNG2dwsEC0NdE8kijB8oPXIMp441wVh0u+
         Lg1qdB6kiEZAlP4o6BhBh9xt9L6V+Qu0hocpdeoDULCIE9RGhSUY1v7xkvhaO2AusuFZ
         h+DQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWL3rXi1JUgcpTW2YK9f4XlVppzB9c9Wk0DTq6e5f8D6z1S8dFV
	LudWA7F4F9pQ6LXWitSIxv8=
X-Google-Smtp-Source: APXvYqy2g3HVx4i5B2jyEFplbTb3bOxZL3d+JX0I+S6GnWGbKWu66R9PRapMwCJDVYUMGT8h2Lqexw==
X-Received: by 2002:a17:902:758e:: with SMTP id j14mr8024941pll.290.1575540808540;
        Thu, 05 Dec 2019 02:13:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:e701:: with SMTP id s1ls737291pfh.6.gmail; Thu, 05 Dec
 2019 02:13:28 -0800 (PST)
X-Received: by 2002:aa7:989d:: with SMTP id r29mr8359752pfl.142.1575540808108;
        Thu, 05 Dec 2019 02:13:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575540808; cv=none;
        d=google.com; s=arc-20160816;
        b=mQPM4vLmzFsazkCaULRTtKBypISzoWvkA1tF0E6w/rY+yebLkvFqpvS1YpMbNhxQ6+
         GVdi3QeNz2MybGNjWQsra97DM0i1Tb0zGhS4P7wEBjvkldF7IvIcxs+F6a8YvswA7jJX
         HNCPr9iEPFoRLWS4oh5Ig2WkJ2NxumCEmF2RICFPaYqxDRbJ3lNzjgSNevXtmBVgYmRm
         4HpQz/SRzvjqdM7SNpvsqaC++OsheUZBWo3Ed4rb88Wb+Iuabe9SRU/vfthD1wbc27g/
         40hbezbqr75vt/HC72g4M2lu6eEwFGGz7wRvUFyEpZr/OSxIIFpVhXbtLcOH5QZUUAsV
         GwUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:to:subject
         :dkim-signature;
        bh=dLjLck9Pm/snpxos2FeKTPLyXDOV4MbjcH5G/gXnZeo=;
        b=KXVOZX7oxupzxNgAliimX6eUTIDZGP2zfvMh4XTZVdKuC8+0ySjLzpyCGRoFmwDx4i
         dpjx4lQvlnvCSLdFap0/HmpkVpiTmzfYZfm6JUz+7xujf3Q50G+AYs8D77j7KtLYNYH3
         67IGxwlCd2bq3+TjqaTrLdaAs4FF55Qc4uAFdI0aaV7Jt3Dtn2IQeFXTy6Jq5jEJOe7w
         hSCDHvA9+4txveoFk2Gk1VLJml/1w94CDVrcGjx381+1MUHTe3adUGBn+bBoUw4hL2up
         g5RjPdqPsUSxB6rG7rIH0NaMXHQcXl4J5ovvH41hy264eD1zydRYx1tycn1NmxgePacP
         yH4A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=caA7vTLu;
       spf=pass (google.com: domain of pbonzini@redhat.com designates 205.139.110.61 as permitted sender) smtp.mailfrom=pbonzini@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-1.mimecast.com (us-smtp-1.mimecast.com. [205.139.110.61])
        by gmr-mx.google.com with ESMTPS id h18si409048pju.1.2019.12.05.02.13.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 05 Dec 2019 02:13:28 -0800 (PST)
Received-SPF: pass (google.com: domain of pbonzini@redhat.com designates 205.139.110.61 as permitted sender) client-ip=205.139.110.61;
Received: from mail-wr1-f69.google.com (mail-wr1-f69.google.com
 [209.85.221.69]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-344-mahgg2fIP52RTxRdcWzmFg-1; Thu, 05 Dec 2019 05:13:23 -0500
Received: by mail-wr1-f69.google.com with SMTP id y7so535148wrm.3
        for <kasan-dev@googlegroups.com>; Thu, 05 Dec 2019 02:13:23 -0800 (PST)
X-Received: by 2002:adf:ee88:: with SMTP id b8mr9668764wro.249.1575540802663;
        Thu, 05 Dec 2019 02:13:22 -0800 (PST)
X-Received: by 2002:adf:ee88:: with SMTP id b8mr9668720wro.249.1575540802410;
        Thu, 05 Dec 2019 02:13:22 -0800 (PST)
Received: from ?IPv6:2001:b07:6468:f312:541f:a977:4b60:6802? ([2001:b07:6468:f312:541f:a977:4b60:6802])
        by smtp.gmail.com with ESMTPSA id b10sm11809139wrt.90.2019.12.05.02.13.20
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Dec 2019 02:13:21 -0800 (PST)
Subject: Re: KASAN: slab-out-of-bounds Read in fbcon_get_font
To: syzbot <syzbot+4455ca3b3291de891abc@syzkaller.appspotmail.com>,
 aryabinin@virtuozzo.com, b.zolnierkie@samsung.com,
 daniel.thompson@linaro.org, daniel.vetter@ffwll.ch,
 dri-devel@lists.freedesktop.org, dvyukov@google.com, ghalat@redhat.com,
 gleb@kernel.org, gwshan@linux.vnet.ibm.com, hpa@zytor.com,
 jmorris@namei.org, kasan-dev@googlegroups.com, kvm@vger.kernel.org,
 linux-fbdev@vger.kernel.org, linux-kernel@vger.kernel.org,
 linux-security-module@vger.kernel.org, maarten.lankhorst@linux.intel.com,
 mingo@redhat.com, mpe@ellerman.id.au, penguin-kernel@i-love.sakura.ne.jp,
 ruscur@russell.cc, sam@ravnborg.org, serge@hallyn.com,
 stewart@linux.vnet.ibm.com, syzkaller-bugs@googlegroups.com,
 takedakn@nttdata.co.jp, tglx@linutronix.de, x86@kernel.org
References: <0000000000003e640e0598e7abc3@google.com>
From: Paolo Bonzini <pbonzini@redhat.com>
Message-ID: <41c082f5-5d22-d398-3bdd-3f4bf69d7ea3@redhat.com>
Date: Thu, 5 Dec 2019 11:13:17 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.1.1
MIME-Version: 1.0
In-Reply-To: <0000000000003e640e0598e7abc3@google.com>
Content-Language: en-US
X-MC-Unique: mahgg2fIP52RTxRdcWzmFg-1
X-Mimecast-Spam-Score: 0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: pbonzini@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=caA7vTLu;
       spf=pass (google.com: domain of pbonzini@redhat.com designates
 205.139.110.61 as permitted sender) smtp.mailfrom=pbonzini@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 04/12/19 22:41, syzbot wrote:
> syzbot has bisected this bug to:
>=20
> commit 2de50e9674fc4ca3c6174b04477f69eb26b4ee31
> Author: Russell Currey <ruscur@russell.cc>
> Date:=C2=A0=C2=A0 Mon Feb 8 04:08:20 2016 +0000
>=20
> =C2=A0=C2=A0=C2=A0 powerpc/powernv: Remove support for p5ioc2
>=20
> bisection log:=C2=A0 https://syzkaller.appspot.com/x/bisect.txt?x=3D127a0=
42ae00000
> start commit:=C2=A0=C2=A0 76bb8b05 Merge tag 'kbuild-v5.5' of
> git://git.kernel.org/p..
> git tree:=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 upstream
> final crash:=C2=A0=C2=A0=C2=A0 https://syzkaller.appspot.com/x/report.txt=
?x=3D117a042ae00000
> console output: https://syzkaller.appspot.com/x/log.txt?x=3D167a042ae0000=
0
> kernel config:=C2=A0 https://syzkaller.appspot.com/x/.config?x=3Ddd226651=
cb0f364b
> dashboard link:
> https://syzkaller.appspot.com/bug?extid=3D4455ca3b3291de891abc
> syz repro:=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 https://syzkaller.appspot.com/x/=
repro.syz?x=3D11181edae00000
> C reproducer:=C2=A0=C2=A0 https://syzkaller.appspot.com/x/repro.c?x=3D105=
cbb7ae00000
>=20
> Reported-by: syzbot+4455ca3b3291de891abc@syzkaller.appspotmail.com
> Fixes: 2de50e9674fc ("powerpc/powernv: Remove support for p5ioc2")
>=20
> For information about bisection process see:
> https://goo.gl/tpsmEJ#bisection
>=20

Why is everybody being CC'd, even if the bug has nothing to do with the
person's subsystem?

Thanks,

Paolo

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/41c082f5-5d22-d398-3bdd-3f4bf69d7ea3%40redhat.com.

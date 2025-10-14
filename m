Return-Path: <kasan-dev+bncBDAOJ6534YNBB456W7DQMGQEJO3WE5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 11646BD76B9
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Oct 2025 07:28:21 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-634741fccc9sf4878112a12.2
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Oct 2025 22:28:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760419700; cv=pass;
        d=google.com; s=arc-20240605;
        b=V8J5gx/bU4bc8YPM7apAJJK5ANQwd4QT6HvJj0plsReaixIYY42QOAf8W1l/5k8Y4R
         dFe2Izt/NWyC81+C7mq3+L+0ctVCEZtn83Tk44ekZw9io5tIkUrvOVk0Q3wV/aAdkNmO
         IOrxf++Whd5hT2vW4OvDtDxyO52NbK3RsHg+WK833LcYlcP02sEz9fXsFqPw01raPDAy
         ObFRlqKMsOGNSPd3vmwNj5iuU1/4t33lZTK5MiSYh6z6YReHY+KPL8iP/rDEYB7Volxg
         YLPiJ+2dog9d5p1LdVrSclrP2taxhciTRu/IpwXt/x0xItTxkWzMhH81M2eEgT2oNLBf
         S42Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=ayD54PC72A5z0PZWiywE86XQlQFh//twUh4nL3p2moA=;
        fh=kICxaX4eHnyjkeX16hscdLkToAzoGRKsMU7aoAkLhZY=;
        b=DsJbnxjzzO2fnYuGSyhA9hW59LEevD/n9lC9IFYACfXaDzmk5f3supiTVgNldCZRci
         FqjfuyLndPBVrq8WVm3rZqbAnq2LrmVfV8a/FtvPtPUwRPy1KoB8i0nqi7jBU+v9LftA
         zm5iGo2PxHL/70W5cWAX9Qt9pzq94c+AcHUq4281ruA031yPdQPyhVPwY9M+5dxGjkPt
         JZ4wn6oe+CLBvfC975Mf3ApXC67aK7m4nIvtugwWv35vT1ACCtBzpOx3hHsVDwnYhYv6
         yo1qSM5BsrWJKjYRqXQ8Ft3SBdDt+eSGIJf19S6glvjjsgtU3PKVrVlopM+mNP4DiRqv
         Jkwg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=P1uPe3JG;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760419700; x=1761024500; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ayD54PC72A5z0PZWiywE86XQlQFh//twUh4nL3p2moA=;
        b=o3wyGyt4Cn0Nw3ZjOuohKs2pu7UW3ErNUWmBoGdBo2s5F7pPoes+vf1cx/NhQpojkl
         B3L78xaeYO1FaF5dFzgkEy5wTY80V+7WgK5hZ4BCb+JkvIVm0i/RuMqOKRC+Iauf5RVN
         RuDtaYjgWhUpS4Oj/M3Ek8v4HQ7zUapQ70PR2CagQgsdDb5+D7lZE3/g4rplLGE2vGV/
         aZVGNCUQkGLcM8XKvIWYNxUw5PD6RNJnFuFbK4VemOto+ogcnUZ4/3TDjCYkv5EuTmS3
         zzpvY4OMxHSXn8Loqas1Y30UafdI6jElGA3XiJaiNaJUZAdCvFHiWvkGiVnKUBBxpdPi
         wiyg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1760419700; x=1761024500; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ayD54PC72A5z0PZWiywE86XQlQFh//twUh4nL3p2moA=;
        b=BpvFGuaFo6/bMYrXRVpfCAzkv1CHFJOR0ZxjM5B/uU/+x87EbL34WgRyxaUS13zi39
         lIY9EL0wo1+LJBe/+LLj+Pm/WvsDGwQAGthyYavZEG0+pOBMlY736P3y74cK7XT5gUcB
         97SrSyZyfOWKJvM07juN9Orfe+xY3NhzZePMQqF0xErYinwInzSUp5SGMkh2YgXhOiGF
         sch+wrzD+PeLnIiUWwMEnkvqoq0cXh6uI2a8Z6QIYWyY9swjx68o0eUnPPH2xq5ssOR7
         0N5jac6hluyiAbFYC66/zPzKdwzkHL/+BWiS7rh8TOcA7K6+y9I+ZH5wd2AgitZeg49E
         ySrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760419700; x=1761024500;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ayD54PC72A5z0PZWiywE86XQlQFh//twUh4nL3p2moA=;
        b=hwRTtKVcfH/Key+xawK4XyqrkTHEFmqbE5UoVN+ayoSEMOEDabJj4eSBvOWRaN2jCL
         ElvZSBjjyZrQucHHDeHB8NcdQx5kxNZ539KHerjP5vHAH+ev8GwYc7WiJHQCQ84qoP/W
         18YGc2z/WbTEHyI6RudnG4IUlUJ/0FkOlgsYakyV/BPpWpf0oUiPG/rZ1wpkkEUQaQ0o
         B9d2auVQTFWbhCfogBRtbchAVXQ7DKwO5OR06fBXTlphX+sYN5shuq5RxHvVb9dyJRqi
         bFVVL/qVUU9XbiXGt1whtQ8RI730BPzQ4IpGCHGGpaKv7ttgeRteQzg+FywhhC44lM8Z
         a1qw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVswEi45DBxZh+57r4UY88TwFeSCah7iMUGclCp3O9nIxHgIn9vU9AiD8kLQoILzlAg/xu1JA==@lfdr.de
X-Gm-Message-State: AOJu0Yz2vUSO10lHua4Ixed9cF0gLiS5Jnko4ajKn7oJszWkdRbHQR/H
	8/VqraS2jDXx4q2iWlUxOXqhJ8UhhwAD2Ps87Iv+QJpsCNmldwU32yx0
X-Google-Smtp-Source: AGHT+IEa8nQZELUCZkZbk9FqMqzZaTA//9GQHGM3QlHMNCD8sD0/cW8WkkSkmDKdfbUP/PvDQJPlPw==
X-Received: by 2002:a05:6402:2744:b0:637:dfb1:33a8 with SMTP id 4fb4d7f45d1cf-639d5b64901mr22724946a12.3.1760419700225;
        Mon, 13 Oct 2025 22:28:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5T8af5ANsfUPJAsEkucB+3MMthGOUm8N6LV/M0V/2zxw=="
Received: by 2002:aa7:d6d1:0:b0:634:c2a7:e3b3 with SMTP id 4fb4d7f45d1cf-639f558f83bls5040675a12.1.-pod-prod-07-eu;
 Mon, 13 Oct 2025 22:28:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW0pkYRkWTAe2eeFWuj51TCXVr2h6+WsCZ/5jC74zKUPUuxWnB2Mby/26Rixkymx3fgbtzrb8rNwXg=@googlegroups.com
X-Received: by 2002:a05:6402:5213:b0:633:7017:fcbc with SMTP id 4fb4d7f45d1cf-639d5b8f15dmr19989745a12.15.1760419697721;
        Mon, 13 Oct 2025 22:28:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760419697; cv=none;
        d=google.com; s=arc-20240605;
        b=PMq5+JLnqtNFfsyLFNuNJ4pExk3fhYvmDTgUDrlGf/nVCD8e5s/Orqh+vzxOtovyxg
         Qw2MpGyc/UDvhCQui8G/CAST8oPRIOzU5SFj3SOUQC44U0Ty+bHYTdjmfcpjXvQibalN
         NMV5Nb+Zms9VZcEgRS77qB4m113lvnOipe7Ac7sZhyyHGzxlVKF8WvTQhb5Tw6HPk1QZ
         tG/O94JdAD6PMu2PUwJoShypR7EenWsgZvS+HUjGsEFZ0lGmU8chWPGvULFUboqNTCYI
         v0q35vaTWryDSwtORLwilFsBCTwg+YD2Hq53QtC3VSSdfJ868VM0Qm4umBL+bAcf5DFt
         9o9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ptPHbzU60TAIm8mnnxk2ahAv+Cxa99UUvkWsQlBP2xU=;
        fh=X65ejqG4TfITVhjFAhChqY+Yrymbxm0KuJxoBom1ffw=;
        b=WiOQ8nJIuxkPfxho0uOxMyJeJF72I66ud8vgiONROqIynKgrSeHEyxqAw03kKK15ME
         dekysbmdWcMGE93EKu4xNqCZiMyhH1Q2ivWOF+eOw2forRAxGplwmy3iPLRtzTSaXEOx
         8qczSSY0WsttRAaA3FK1zRin393dZVroAT5YCV47GPjfSpA6QjnAdkRFg8MyGqV9YbIw
         wTqUsmQTbRkv7x1bXuJdC7LK5QfcqAd8jVRtEKgrBcE4FYisVh+NYpWpVdF+jfG+Qo8m
         xcajn7BuOaG9WEmaVIxLbWFFh3MfS7Zz1o4zteSNwqu7JI/BWl4X8nw6Ii4WtImzVkVD
         oIGg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=P1uPe3JG;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x131.google.com (mail-lf1-x131.google.com. [2a00:1450:4864:20::131])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-63b97424470si71833a12.5.2025.10.13.22.28.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Oct 2025 22:28:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) client-ip=2a00:1450:4864:20::131;
Received: by mail-lf1-x131.google.com with SMTP id 2adb3069b0e04-57b35e176dbso5939261e87.1
        for <kasan-dev@googlegroups.com>; Mon, 13 Oct 2025 22:28:17 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWlpcCbLm2T7K4AoAcorr1rzz2lwpgFeEhJAxCpxAERDA0+AVwH8O7OXkRh8uM0qX3Fcbvfyo5MUTY=@googlegroups.com
X-Gm-Gg: ASbGnctaW/AcGsDVwzG2BrmJ8TB/xG9q3N8i+Eje8cuCVF+ZaPuUVGPGIPiSodQdTjE
	+14xWYMc+PQb4bggLJRNayZEobXPuVSaDOz8Qh8ljWGCaXQNc6/o/DDfIhUcTOsmpgHZ9PY3Dw1
	CQ2zQnrMVw84des9Grwg3eMSVtoOLUiBgXVM5jqaxLoNXikZcyi0j+D4bFIys3RfpRiJ2dOoqrF
	vbTFNtsHUsYlDXI4T1O1UTFiQ==
X-Received: by 2002:a2e:bcc7:0:b0:372:950f:2aff with SMTP id
 38308e7fff4ca-37609e0ed4emr64933311fa.27.1760419696692; Mon, 13 Oct 2025
 22:28:16 -0700 (PDT)
MIME-Version: 1.0
References: <20250820053459.164825-1-bhe@redhat.com> <CA+fCnZdfv+D7sfRtWgbbFAmWExggzC2by8sDaK7hXfTS7viY8w@mail.gmail.com>
 <aLlJtTeNMdtZAA9B@MiWiFi-R3L-srv> <CA+fCnZf2fGTQ6PpoKxDqkOtwcdwyPYx2cFwQw+3xAjOVxjoh6w@mail.gmail.com>
 <75a2eb31-3636-44d4-b2c9-3a24646499a4@gmail.com> <CA+fCnZf7jYPUyqHqonWhDKVi9eeN6aaaByMTBYCQrv2-8+hngQ@mail.gmail.com>
 <aMfWz4gwFNMx7x82@MiWiFi-R3L-srv> <CA+fCnZcWEuBerMeS4RCXQtged06MJhY=55KsYeJEOJn3K0psXQ@mail.gmail.com>
 <aNNY1AzfGua3Kk3S@MiWiFi-R3L-srv> <CACzwLxh10=H5LE0p86xKqfvObqq+6ZN5Cs0hJ9i1MKJHWnNx2w@mail.gmail.com>
 <aNTfPjS2buXMI46D@MiWiFi-R3L-srv>
In-Reply-To: <aNTfPjS2buXMI46D@MiWiFi-R3L-srv>
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Date: Tue, 14 Oct 2025 10:27:59 +0500
X-Gm-Features: AS18NWDpoAnK8X4S74wzUC_xmUwiiptVaXx4Fi_Po4Ht89THf-aVMKFaVW0-Q-g
Message-ID: <CACzwLxiJ0pGur42Vigq=JnYecyZn-Z5BC3VcqxSUttT54kEusA@mail.gmail.com>
Subject: Re: [PATCH v3 00/12] mm/kasan: make kasan=on|off work for all three modes
To: Baoquan He <bhe@redhat.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, glider@google.com, 
	dvyukov@google.com, elver@google.com, linux-mm@kvack.org, 
	vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	kexec@lists.infradead.org, sj@kernel.org, lorenzo.stoakes@oracle.com, 
	christophe.leroy@csgroup.eu
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=P1uPe3JG;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::131
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Thu, Sep 25, 2025 at 11:21=E2=80=AFAM Baoquan He <bhe@redhat.com> wrote:
>
> On 09/25/25 at 12:07am, Sabyrzhan Tasbolatov wrote:
> > On Wed, Sep 24, 2025 at 5:35=E2=80=AFAM Baoquan He <bhe@redhat.com> wro=
te:
> > >
> > > On 09/23/25 at 07:49pm, Andrey Konovalov wrote:
> > > > Since the Sabyrzhan's patches are already in mm-stable (and I assum=
e
> > > > will be merged during the next merge window), just rebase your chan=
ges
> > > > on top.
> > >
> > > That's fine, I will rebase.
> > >
> > > >
> > > > But also note that Sabyrzhan is planning to move out the
> > > > kasan_enabled() checks into include/linux/kasan.h (which is a clean=
-up
> > > > I would have also asked you to do with the kasan=3Doff patches), so
> > > > maybe you should sync up with him wrt these changes.
> > >
> > > Hi Sabyrzhan,
> > >
> > > What's your thought? You want to do the cleanup after my rebasing on
> > > your merged patches or you prefer to do it ahead of time? Please let =
me
> > > know so that I can adjust my posting accordingly. Thanks.
> > >
> >
> > Hello,
> >
> > I can make all necessary changes only next week. Currently, traveling.
> > I will send the fix-up patch Andrey has described somewhere next week.
> > Please let me know if it's ok.
>
> Please take it easy, today is Thursday, I will wait for your clean up
> patch next week and post. I can do some preparation work for rebasing on
> your merged patches. Thanks.

Hello,

Just heads up that I've already sent cleanup patches [1] and
Andrew has merged them into mm-new tree.
Hopefully, one week's delay wasn't a problem.

[1] https://lore.kernel.org/all/20251009155403.1379150-1-snovitoll@gmail.co=
m/

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ACzwLxiJ0pGur42Vigq%3DJnYecyZn-Z5BC3VcqxSUttT54kEusA%40mail.gmail.com.

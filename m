Return-Path: <kasan-dev+bncBDS5HZF3QMGRBOFQRG7QMGQELKJXFXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id BAD83A6EA38
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Mar 2025 08:16:10 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-3032f4eca83sf4280082a91.3
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Mar 2025 00:16:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742886969; cv=pass;
        d=google.com; s=arc-20240605;
        b=PAFd+tRR5ObdarVmfbT3XkWXodFVbgfVAM2cooUwpCEcPQZUXtoDlHd/QYrx0EXC/1
         7+uPEnwqlQQ4qqkCE/ThUTw/bh+z6rQvqYvc83j9xHAJYrx2HXx/fLGAMrcPqsToruyt
         i9o1/YmcLCVC6JC75wZC9BfDmjmapmD1w86LHyG5AIzm4gm5p4bKUKVXt7jVPg5Qc6Bq
         cEJrosaj5ctxGWSqA1E1ATn2cz+RTk3LlJxLsdWmf/zsUJr3rQCAFU7yqWxmq9j6qFBc
         KvfmwF2VzP5NnNk1uCMG6kRw2so5/WS3mOQaSfyTX6RojvkDbvRSYKDSvFJjKZw6Ay7Y
         IBUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=IMSZKQenrjR3jp17qn1+aTbAvQLAFx9Ml1IHcy/gcBI=;
        fh=Y9zK48MLMVRkPZcibXSH0PKPAz+pZi+PbLOnqFtqbBE=;
        b=dNafylCTue+Hwz7EXsOVZvziEaqdmMKvLdrOvLlfTqCwE7w/qDgDh7njbz8okm/TOC
         hXaBdyRnFg9EVExH1IHyFctXTglNuIDuF/1Ihj9THrj9lV/3THQTPtz7UC/Xdfi4Z/lv
         nf/CmrZZukIxxYnrltHIMpJHCo1kefCtGiXM4EIe9HHA4Y9x8T0j2xnIP18ULU27WWpj
         aUe3bdha8DG9kyDD8RIiJpkX9mbzOF9A80KxVTKsmS/MxPNIOitL3RTMjEKRHsVWdwbz
         poY+vq3gIdyRGi8PARKCt26vWNnRtsSys1yacJd/TtZ6hGtNaomJcTaWpKtCW54IKZlh
         Cd3A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="Rr82g/OX";
       spf=pass (google.com: domain of davisarmstrong75@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=davisarmstrong75@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742886969; x=1743491769; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=IMSZKQenrjR3jp17qn1+aTbAvQLAFx9Ml1IHcy/gcBI=;
        b=WjsXcsBZ5KeUMu6MWG74izxJ0rJCQowWYe3r7FgPSPrXnBo50OTt7rjMcZpr2jSm6x
         mT5HZ8dpLJ/8ufbNXa61a3Ric07f5aAXOeKbjKoXFHdENI24sgjEXt/q1TdazOuJkTgZ
         Tsws6Ondft6AZNzhMMhkgCRGpl0wnrgPbK9Olu246DntL79yl6/JCI6nCmyF4GyhyK7+
         Xo6kiepx6aUPnKkUtEvPqZZLIQ5rMspAbnKLavhRz9gZnZP8lufJTXb9CDPO0UNaZQrH
         QsdpOwwNUyhGvTyLLcc4VlHWGBqN9RKnIvXJFF1GBt2AR6XDD1usNTEQTcsxDZmqV/HH
         N8Gg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1742886969; x=1743491769; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=IMSZKQenrjR3jp17qn1+aTbAvQLAFx9Ml1IHcy/gcBI=;
        b=kECiglpnstXgxKDdWzSKN8+VjUCN3UKE6bl/YvNZTD1uHvrwkn2iKUotcJqbNRvcmy
         0BCdSBV8YQh19CzYfzu5Dkao/wd+nV4n0it2F3ob+4gQzC5EbJd2q1rbCzljiMUKi+Ne
         g8DFrYbQ7gZ2y6QIIz9VLEhnwIKTAbVZhfP5xoN/6Nk52du5tGYiVbVzaK3p705z/pVw
         CTfM4T0Eg5QZnY7BtgnlWpnbUnBNEqFzLnMNg3SbcEysxgsJMFSTgozp4IgZKEobhm7N
         AywqSBdF3W/SkHy28/XECa+LUpz3zfoVOEcYK7H97jC5Qy0dCm2OBEfroRUzE0LTDhpo
         Ddpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742886969; x=1743491769;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=IMSZKQenrjR3jp17qn1+aTbAvQLAFx9Ml1IHcy/gcBI=;
        b=b1uUt8R0YCoPNTo8xbHhvcc9kGyBIrkkr9QjK683yC1N2JNSpJv+nge4pwK4HFkeTG
         Y04lBKxLbqVAmyaoRwKYl+ptrXotKvuvs0Po7u2SjF5yNRgWzndEVvbUYlVHV7E/6+7S
         v4mJr5ySstZRTSYv0aXrf7oQyiWutaFw/fOtuXPqCdMTMk6lOhM/YoHiTvWZQhBVTn5E
         7+6eVfzIT0JwvNz4UNmo67S1TOanvAW1qxSEdgeF2F94pBGmnuy240oA4Wtf4M3L4XaT
         QKmPeuR+bVJUumwOS/sx4FnHk5Vx5vUMGMUsvB6N411wUzX+ruLMTFaamMg2hH9dZLGg
         6qqA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXYPzhSTrvfpNy96wWuLglZJnFc+7TFILjClOVJFOtz9znq9EXqDwzZLo9F+3x4tedAm+T7vw==@lfdr.de
X-Gm-Message-State: AOJu0YwPhmw+eVN+ArqZj3zzwmPuHkEzl+uyj9reHfTSmZR2idhOqc2K
	QYZ7EhpqmKgUxh1nWOILck9XrTEa6Nq0cKk/wiGmYzhPtyEVVzzY
X-Google-Smtp-Source: AGHT+IG0UgNRMkdaMz6/GVNKn5fkiRBWFoqjNleGdk1S1foEoNL+KO9hawgfZXgLzbdKgSS+c0+VSA==
X-Received: by 2002:a17:90b:3a8f:b0:301:1d03:93cf with SMTP id 98e67ed59e1d1-3031002a5a8mr20280657a91.30.1742886968533;
        Tue, 25 Mar 2025 00:16:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIPTNUIosLhccN34d9zYNyJKUN7Xp5GY+8WcTf0RbRQcg==
Received: by 2002:a17:90a:d489:b0:2ff:4b14:3df0 with SMTP id
 98e67ed59e1d1-301d4589220ls2737368a91.0.-pod-prod-04-us; Tue, 25 Mar 2025
 00:16:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXwtY1EXzoPVz2sOZrD6y8P5Tmb08wR9WNqyRKmfEqvtiAWHmeVEmozGDZzPeRJPR5FZ9tmrFRA7ok=@googlegroups.com
X-Received: by 2002:a17:90b:3b42:b0:2fe:9581:fbea with SMTP id 98e67ed59e1d1-30310024becmr21409218a91.29.1742886967080;
        Tue, 25 Mar 2025 00:16:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742886967; cv=none;
        d=google.com; s=arc-20240605;
        b=b71Shi/ByTUKUAhqBY7/3b8RpgbP5uXbvwIG2BXsjkKbhFQ0u04aPnGZWNJoGG7yUv
         XGdpdgjn1h2h6c7zMlCh91gyYodPFqPXuFmMGGlwHD07VYbdUMA3diNxL197H7z70hSv
         dzEvZbMNtl/TZdLc9j5loryTR0xU9sdUU8TJYzV2v8FvPB3GhJvHqOfVQiIdm6e9Gxc0
         +oZba8csEdRjANT9ZgppFBYryPz0f5/L7VeUlvhhVOHAi34EEZPEloRHvcbecGe+aHmM
         pB7+TJ5rZqTz0KASvYhzHce3caJAy8t5pU0n6c1a72szATCTLqsBf9JX+98ac1ENMiab
         ZyzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=BN/R8GZqEq3Xt/qZLJJLpuZWGzJDXmFjyiV4GwlgjOY=;
        fh=wQZAB+auIsKmyEKvvLBi9pgkncKchRAGk9s4xSA+YA8=;
        b=WO/rvgOkaU3yqhdWRmmgU8C+cdcz0UiZT7w6UyUuGQ9/8d7rIGM+Qy0y8DbTErcvbe
         ZjcUrAS12xPH9hmcjpCJMsHAIao8UFS59pH5m8OMYwi9Wco5H3vUU+i+oNHbcS/5F/Ga
         CZneh3gf5wh7GTQwAXxlJa9aFip4vxQAC6iWNNlXLajMkT9Dnmklsc+7vEKby0sTcOKd
         cG3+mBqY1N9VfsIWXhIEZ7v7yCmWEAxxt0nqUyf59v4arUf93OYPym30CtLfWtUKzaL0
         hlJEw6UUiCcUSP5c1W5NGwZGky2005L5pEizttiQg+0YAznphwS2RZmS6Zk/l7ucDE3E
         VhvA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="Rr82g/OX";
       spf=pass (google.com: domain of davisarmstrong75@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=davisarmstrong75@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x633.google.com (mail-pl1-x633.google.com. [2607:f8b0:4864:20::633])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3036c93f1b3si86830a91.1.2025.03.25.00.16.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 25 Mar 2025 00:16:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of davisarmstrong75@gmail.com designates 2607:f8b0:4864:20::633 as permitted sender) client-ip=2607:f8b0:4864:20::633;
Received: by mail-pl1-x633.google.com with SMTP id d9443c01a7336-227aaa82fafso46440955ad.2
        for <kasan-dev@googlegroups.com>; Tue, 25 Mar 2025 00:16:07 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVcDAqdOAa6jd+0cwyMc3acLXkJgwI7MlwoyIsqmfSGxQm9wLK+PJlYqvEgJ3okkLJhuiuhLIoSmMY=@googlegroups.com
X-Gm-Gg: ASbGncstRz3fnVGTS22KypfhbW1Bm1TZ3BieUalnLIlDBoiVqbAjwCH5M+VS1f4k+cI
	aF8MXf0qvHH1xbN5+AKNdhQ1ELQX6DXfuBb5qetgAI8yWd492VxE46K78395Li1ZKRK5KHPkI7M
	Xpoberrkd1xRTUZcf9zpnuJaC+Fw==
X-Received: by 2002:a17:902:e5c8:b0:220:e1e6:4457 with SMTP id
 d9443c01a7336-22780d8b043mr197759665ad.26.1742886966465; Tue, 25 Mar 2025
 00:16:06 -0700 (PDT)
MIME-Version: 1.0
From: Barrister David House Cyril <davisarmstrong75@gmail.com>
Date: Tue, 25 Mar 2025 08:15:56 +0100
X-Gm-Features: AQ5f1Jq4PIDt-DFtpuZIsS60wZnDdW-OKxYp5VH0IQBjDRfQI7_VZz1yFu-Ql7g
Message-ID: <CACLqPKA10SUAarmcfcSBTvs0CV1vp_AqD81VaOfmBccU+p4wpA@mail.gmail.com>
Subject: REPLY
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="000000000000854e6f0631257eb0"
X-Original-Sender: davisarmstrong75@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="Rr82g/OX";       spf=pass
 (google.com: domain of davisarmstrong75@gmail.com designates
 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=davisarmstrong75@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
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

--000000000000854e6f0631257eb0
Content-Type: text/plain; charset="UTF-8"

Greetings,
I'm  Barrister House Cyril, from Benin Republic. A private attorney to your
late family relative, who died together with his wife and their only
daughter in the New York's Train Crash On February 3, 2022, which
unfortunately killed 6 people and wounded about a dozen others.

My client died without a will. And now the bank contacted me as his private
lawyer, to present a beneficiary.

Since you have the same surname and come from the same country, I want to
present your name to the bank. Let the bank transfer to you the sum of  ($
58.3 millions dollars) . Then I will come to your country, you and I will
share the money 45% for me and 45% for you, then 10% to the Orphanage. I
don't want you to worry about the legal part of the transaction because
I'll guide the transaction so that it will go in line with the law in our
favor. I will need the following information from you to enable me furnish
you full details on how to achieve this;

Your Full Name:-------------
Address: ------------------
Your Age:-------------------------
Occupation:-----------------------------
Your Telephone, and Mobile for Communication Purpose:--------------------

I await your urgent reply then I will give you more information.

With respect,
Barrister House Cyril

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CACLqPKA10SUAarmcfcSBTvs0CV1vp_AqD81VaOfmBccU%2Bp4wpA%40mail.gmail.com.

--000000000000854e6f0631257eb0
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><br>Greetings,<br>I&#39;m =C2=A0Barrister House Cyril, fro=
m Benin Republic. A private attorney to your late family relative, who died=
 together with his wife and their only daughter in the New York&#39;s Train=
 Crash On February 3, 2022, which unfortunately killed 6 people and wounded=
 about a dozen others.<br><br>My client died without a will. And now the ba=
nk contacted me as his private lawyer, to present a beneficiary.<br><br>Sin=
ce you have the same surname and come from the same country, I want to pres=
ent your name to the bank. Let the bank transfer to you the sum of =C2=A0($=
 58.3 millions dollars) . Then I will come to your country, you and I will =
share the money 45% for me and 45% for you, then 10% to the Orphanage. I do=
n&#39;t want you to worry about the legal part of the transaction because I=
&#39;ll guide the transaction so that it will go in line with the law in ou=
r favor. I will need the following information from you to enable me furnis=
h you full details on how to achieve this;<br><br>Your Full Name:----------=
---<br>Address: ------------------<br>Your Age:-------------------------<br=
>Occupation:-----------------------------<br>Your Telephone, and Mobile for=
 Communication Purpose:--------------------<br><br>I await your urgent repl=
y then I will give you more information.<br><br>With respect,<br>Barrister =
House Cyril</div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/CACLqPKA10SUAarmcfcSBTvs0CV1vp_AqD81VaOfmBccU%2Bp4wpA%40mail.gmai=
l.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/m=
sgid/kasan-dev/CACLqPKA10SUAarmcfcSBTvs0CV1vp_AqD81VaOfmBccU%2Bp4wpA%40mail=
.gmail.com</a>.<br />

--000000000000854e6f0631257eb0--
